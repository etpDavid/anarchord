//! Espaços de conversa: o Lobby público e os servidores (comunidades com dono).
//!
//! - **Lobby**: sem dono e sem moderação; qualquer nome vira canal. É onde as pessoas se
//!   encontram pela primeira vez e trocam convites de servidor.
//! - **Servidor**: definido por uma cadeia de blocos assinada pela chave do servidor
//!   ([`chain`]). Quem participa tem um passaporte ([`passport`]); moderadores assinam ações
//!   ([`cert`]) com o próprio passaporte, e carimbos de tempo ([`timestamp`]) ordenam tudo.
//!   Os canais de cada servidor ficam num namespace próprio de tópicos.
//!
//! Este módulo contém só lógica (sem rede nem interface): o loop de eventos publica as
//! mensagens que ele devolve e repassa a ele as que chegam.

pub mod cert;
pub mod chain;
pub mod e2ee;
pub mod passport;
pub mod timestamp;

pub use cert::{format_duration, parse_duration, ModAction, ModKind, UtcSecs};
pub use chain::{AppendResult, BanState, Block, Channel, ChannelType, Entry, Rejection, ServerChain, ServerState};
pub use passport::{PassportError, PassportPermission, ServerPassport};
pub use timestamp::{PeerTimestampToken, TimestampAttestation, TimestampPolicy, TrustedTsa};

use crate::identity::{hex_decode_32, UserIdentity};
use chain::{DEFAULT_PASSPORT_VALIDITY_SECS, DEFAULT_RENEWAL_WINDOW_SECS};
use libp2p::kad;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

const TOPIC_PREFIX: &str = "p2p-anarchord";
/// Blocos por mensagem ao responder um pedido de cadeia (mantém cada mensagem bem abaixo de 1 MB)
const BLOCKS_PER_MESSAGE: usize = 32;

/// Onde o usuário está conversando
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Space {
    Lobby,
    Server(String),
}

/// Tópico Gossipsub de um canal de texto. No Lobby mantém o formato original
/// (`p2p-anarchord/channel/<canal>`), compatível com nós anteriores.
pub fn channel_topic(space: &Space, channel: &str) -> String {
    match space {
        Space::Lobby => format!("{}/channel/{}", TOPIC_PREFIX, channel),
        Space::Server(id) => format!("{}/server/{}/channel/{}", TOPIC_PREFIX, id, channel),
    }
}

/// Tópico Gossipsub de uma sala de voz
pub fn voice_topic(space: &Space, channel: &str) -> String {
    match space {
        Space::Lobby => format!("{}/voice/{}", TOPIC_PREFIX, channel),
        Space::Server(id) => format!("{}/server/{}/voice/{}", TOPIC_PREFIX, id, channel),
    }
}

/// Tópico de compartilhamento de tela do espaço
pub fn screen_topic(space: &Space) -> String {
    match space {
        Space::Lobby => format!("{}/screens", TOPIC_PREFIX),
        Space::Server(id) => format!("{}/server/{}/screens", TOPIC_PREFIX, id),
    }
}

/// Tópico dos quadros de uma transmissão de tela: só quem assiste se inscreve
pub fn screen_stream_topic(space: &Space, stream_id: &str) -> String {
    format!("{}/{}", screen_topic(space), stream_id)
}

/// Se o tópico é de conteúdo de um servidor (canal, voz ou tela), devolve o id do servidor.
/// Esse conteúdo trafega cifrado com MLS.
pub fn parse_server_content_topic(topic: &str) -> Option<&str> {
    let rest = topic.strip_prefix(TOPIC_PREFIX)?.strip_prefix("/server/")?;
    let (id, tail) = rest.split_at(rest.find('/')?);
    let content = tail.starts_with("/channel/") || tail.starts_with("/voice/") || tail.starts_with("/screens");
    (content && is_valid_server_id(id)).then_some(id)
}

/// Se o tópico é de um canal de texto de servidor, devolve (id do servidor, canal)
pub fn parse_server_channel_topic(topic: &str) -> Option<(&str, &str)> {
    let rest = topic.strip_prefix(TOPIC_PREFIX)?.strip_prefix("/server/")?;
    let (id, channel) = rest.split_once("/channel/")?;
    is_valid_server_id(id).then_some((id, channel))
}

/// Tópico de controle de um servidor: blocos da cadeia, ações de moderação e pedidos de cadeia
pub fn server_control_topic(server_id: &str) -> String {
    format!("{}/server/{}", TOPIC_PREFIX, server_id)
}

/// Se o tópico é o de controle de um servidor, devolve o id do servidor
pub fn parse_server_control_topic(topic: &str) -> Option<&str> {
    let id = topic.strip_prefix(TOPIC_PREFIX)?.strip_prefix("/server/")?;
    is_valid_server_id(id).then_some(id)
}

/// Chave de descoberta do servidor na DHT: membros a anunciam, quem entra procura por ela
pub fn server_dht_key(server_id: &str) -> kad::RecordKey {
    let digest = Sha256::digest(format!("anarchord-server:{}", server_id).as_bytes());
    let mut multihash = Vec::with_capacity(34);
    multihash.extend_from_slice(&[0x12, 0x20]);
    multihash.extend_from_slice(&digest);
    kad::RecordKey::new(&multihash)
}

/// O id de um servidor é a pubkey Ed25519 dele em hex (64 caracteres)
pub fn is_valid_server_id(id: &str) -> bool {
    hex_decode_32(id).is_ok()
}

/// Início do id, para exibição
pub fn short_id(id: &str) -> &str {
    &id[..id.len().min(8)]
}

/// Canais criados junto com um servidor novo
pub fn default_channels() -> Vec<Channel> {
    vec![
        Channel { name: "geral".into(), channel_type: ChannelType::Text },
        Channel { name: "voz".into(), channel_type: ChannelType::Voice },
    ]
}

/// Mensagens trocadas no tópico de controle de um servidor
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ServerMessage {
    /// Blocos da cadeia (novos ou em resposta a um pedido)
    Blocks { server_id: String, blocks: Vec<Block> },
    /// Pedido dos blocos a partir de uma altura. Em servidor privado só é atendido com passaporte.
    ChainRequest {
        server_id: String,
        from_height: u64,
        #[serde(default)]
        passport: Option<ServerPassport>,
    },
    /// Ação de moderador ainda não incluída na cadeia
    Action(ModAction),
    /// Pedido de entrada no grupo cifrado (MLS): pacote de chave de quem publicou acompanhado de seu passaporte
    KeyPackage {
        server_id: String,
        #[serde(with = "crate::b64")]
        key_package: Vec<u8>,
        #[serde(default)]
        passport: Option<ServerPassport>,
    },
    /// Commit MLS do líder (adiciona/remove membros ou rotaciona a chave do grupo)
    Commit {
        server_id: String,
        #[serde(with = "crate::b64")]
        commit: Vec<u8>,
    },
    /// Welcome MLS para quem foi admitido no grupo, com os passaportes dos membros atuais
    /// (quem entra valida o grupo e os Commits seguintes do líder com eles)
    Welcome {
        server_id: String,
        target: String,
        #[serde(with = "crate::b64")]
        welcome: Vec<u8>,
        #[serde(default)]
        member_passports: Vec<ServerPassport>,
    },
    /// Anúncio de presença do grupo MLS ativo (líder, época e membros) para convergência determinística
    GroupAnnounce {
        server_id: String,
        epoch: u64,
        leader: String,
        members: Vec<String>,
    },
    /// Oferta/entrega de Passaporte (emissão, renovação ou achatamento de cadeia)
    PassportOffer {
        server_id: String,
        target: String,
        passport: ServerPassport,
    },
    /// Solicitação de Achatamento Oportunista de Cadeia
    FlattenRequest {
        server_id: String,
        passport: ServerPassport,
    },
    /// Quem não tem passaporte pede um. Em servidor público, moderadores com `IssueMember`
    /// online emitem automaticamente.
    AccessRequest { server_id: String },
    /// Pedido de carimbo de tempo a testemunhas da rede (só o hash viaja)
    StampRequest { server_id: String, imprint: String, nonce: String },
    /// Carimbo sobre `imprint` (de uma TSA ou de uma testemunha) para anexar ao objeto correspondente
    Stamp { server_id: String, imprint: String, stamp: TimestampAttestation },
}

impl ServerMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::wire::encode(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::wire::WireError> {
        crate::wire::decode_as(bytes)
    }
}

#[derive(Error, Debug)]
pub enum CommunityError {
    #[error("ID de servidor inválido (esperado: 64 caracteres hexadecimais)")]
    InvalidServerId,
    #[error("Você não está nesse servidor")]
    UnknownServer,
    #[error("A configuração desse servidor ainda não chegou; aguarde algum membro online")]
    NoChainYet,
    #[error("Só o dono do servidor pode fazer isso")]
    NotOwner,
    #[error("Seu passaporte não dá essa permissão neste servidor")]
    NotModerator,
    #[error("Você não possui passaporte válido neste servidor")]
    NoPassport,
    #[error("Ação recusada: {0}")]
    Rejected(Rejection),
    #[error("Passaporte recusado: {0}")]
    Passport(#[from] PassportError),
    #[error("Já existe um canal com esse nome")]
    ChannelExists,
    #[error("Canal inexistente")]
    UnknownChannel,
    #[error("Autoridade de tempo inválida: {0}")]
    InvalidTsa(String),
    #[error("{0}")]
    Identity(#[from] crate::identity::IdentityError),
    #[error("Erro de E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("Erro de serialização: {0}")]
    Json(#[from] serde_json::Error),
}

/// Ação provisória (ainda fora da cadeia) e quando este nó a viu
#[derive(Serialize, Deserialize, Clone, Debug)]
struct PendingAction {
    action: ModAction,
    seen_at: UtcSecs,
}

/// Um servidor que este nó acompanha
pub struct KnownServer {
    pub server_id: String,
    chain: ServerChain,
    /// Presente só se este nó é o dono
    owner_key: Option<UserIdentity>,
    /// Passaporte do nó local neste servidor (emitido pela raiz ou por moderador)
    my_passport: Option<ServerPassport>,
    /// Passaportes conhecidos dos outros participantes (por titular)
    passports: BTreeMap<String, ServerPassport>,
    /// Ações de moderadores recebidas e ainda não incluídas na cadeia (por id)
    pending: BTreeMap<String, PendingAction>,
    /// Estado efetivo calculado, válido enquanto cadeia e ações provisórias não mudarem
    cache: std::cell::RefCell<Option<(StateFingerprint, ServerState)>>,
}

/// O que determina o estado efetivo: topo da cadeia e ações provisórias (com seus carimbos)
type StateFingerprint = (usize, Option<String>, Vec<(String, usize)>);

impl KnownServer {
    fn new(server_id: &str) -> Self {
        Self {
            server_id: server_id.to_string(),
            chain: ServerChain::new(server_id),
            owner_key: None,
            my_passport: None,
            passports: BTreeMap::new(),
            pending: BTreeMap::new(),
            cache: std::cell::RefCell::new(None),
        }
    }

    pub fn has_chain(&self) -> bool {
        !self.chain.is_empty()
    }

    pub fn chain(&self) -> &ServerChain {
        &self.chain
    }

    pub fn name(&self) -> String {
        if self.has_chain() {
            self.chain.state().name.clone()
        } else {
            format!("(aguardando configuração) {}", short_id(&self.server_id))
        }
    }

    pub fn is_owner(&self) -> bool {
        self.owner_key.is_some()
    }

    pub fn owner_key(&self) -> Option<&UserIdentity> {
        self.owner_key.as_ref()
    }

    pub fn my_passport(&self) -> Option<&ServerPassport> {
        self.my_passport.as_ref()
    }

    pub fn set_my_passport(&mut self, passport: ServerPassport) {
        self.passports.insert(passport.body.holder.clone(), passport.clone());
        self.my_passport = Some(passport);
    }

    /// Quantos passaportes de participantes este nó conhece
    pub fn known_passports(&self) -> usize {
        self.passports.len()
    }

    /// Passaporte conhecido de uma pubkey
    pub fn passport_of(&self, pubkey: &str) -> Option<&ServerPassport> {
        self.passports.get(pubkey)
    }

    /// Guarda o passaporte de outro participante se ele for válido e mais novo que o conhecido.
    /// Devolve `true` se mudou algo.
    pub fn learn_passport(&mut self, passport: &ServerPassport, now: UtcSecs) -> bool {
        if !self.has_chain() || self.chain.state().verify_passport(passport, now).is_err() {
            return false;
        }
        let state = self.chain.state();
        let replace = match self.passports.get(&passport.body.holder) {
            None => true,
            Some(known) if known == passport => false,
            Some(known) => {
                // Carimbos só desempatam o mesmo passaporte. Entre passaportes distintos emitidos no
                // mesmo segundo (ex.: membro e logo depois moderador) vence o de permissões
                // estritamente maiores, independente da ordem de chegada (todos os nós convergem)
                let same_second = passport.body.issued_at == known.body.issued_at;
                let same_serial = passport.body.serial == known.body.serial;
                let wider = known.body.permissions.iter().all(|p| passport.body.permissions.contains(p))
                    && passport.body.permissions.len() > known.body.permissions.len();
                state.verify_passport(known, now).is_err()
                    || passport.body.issued_at > known.body.issued_at
                    || (same_second && !same_serial && wider)
                    || (same_second && same_serial && passport.stamps.len() > known.stamps.len())
            }
        };
        if replace {
            self.passports.insert(passport.body.holder.clone(), passport.clone());
        }
        replace
    }

    pub fn channels(&self) -> Vec<Channel> {
        self.chain.state().channels.clone()
    }

    pub fn has_channel(&self, name: &str, kind: ChannelType) -> bool {
        self.chain.state().channels.iter().any(|c| c.name == name && c.channel_type == kind)
    }

    /// Verifica se existe qualquer canal (texto ou voz) com este nome no servidor
    pub fn has_any_channel(&self, name: &str) -> bool {
        self.chain.state().channels.iter().any(|c| c.name == name)
    }

    /// Primeiro canal de texto (onde o usuário cai ao entrar no servidor)
    pub fn default_text_channel(&self) -> Option<String> {
        self.channels()
            .into_iter()
            .find(|c| c.channel_type == ChannelType::Text)
            .or_else(|| self.channels().into_iter().next())
            .map(|c| c.name)
    }

    pub fn pending_actions(&self) -> impl Iterator<Item = &ModAction> {
        self.pending.values().map(|p| &p.action)
    }

    /// Estado efetivo agora: a cadeia mais as ações provisórias, reavaliadas pelo tempo atestado
    pub fn effective_state(&self, _now: UtcSecs) -> ServerState {
        let fingerprint: StateFingerprint = (
            self.chain.blocks().len(),
            self.chain.head().map(Block::hash),
            self.pending.iter().map(|(id, p)| (id.clone(), p.action.stamps.len())).collect(),
        );
        if let Some((cached_for, state)) = self.cache.borrow().as_ref() {
            if *cached_for == fingerprint {
                return state.clone();
            }
        }
        let mut state = self.chain.state().clone();
        if !self.pending.is_empty() {
            state.add_provisional(self.pending.values().map(|p| (&p.action, p.seen_at)));
        }
        *self.cache.borrow_mut() = Some((fingerprint, state.clone()));
        state
    }

    /// Deve ficar fora (do grupo cifrado, do chat): banido sem passaporte que o reabilite, ou com
    /// passaporte conhecido inválido. Quem ainda não anunciou passaporte não é excluído por isso.
    pub fn is_excluded(&self, pubkey: &str, now: UtcSecs) -> bool {
        let state = self.effective_state(now);
        if state.is_owner_key(pubkey) {
            return false;
        }
        match self.passports.get(pubkey) {
            Some(p) => !state.is_allowed_with_passport(pubkey, Some(p), now),
            None => state.is_banned(pubkey, now),
        }
    }

    /// Há ban em vigor sobre a pubkey e nenhum passaporte conhecido que a reabilite
    pub fn is_banned(&self, pubkey: &str, now: UtcSecs) -> bool {
        let state = self.effective_state(now);
        state.is_banned(pubkey, now) && !state.is_allowed_with_passport(pubkey, self.passports.get(pubkey), now)
    }

    /// Participa: dono/chave do servidor ou passaporte válido conhecido
    pub fn is_allowed(&self, pubkey: &str, now: UtcSecs) -> bool {
        self.effective_state(now).is_allowed_with_passport(pubkey, self.passports.get(pubkey), now)
    }

    pub fn is_allowed_with_passport(&self, pubkey: &str, passport: Option<&ServerPassport>, now: UtcSecs) -> bool {
        let state = self.effective_state(now);
        state.is_allowed_with_passport(pubkey, passport, now)
            || state.is_allowed_with_passport(pubkey, self.passports.get(pubkey), now)
    }

    /// Pubkey é moderador agora (passaporte válido com algum poder além de participar)
    pub fn is_moderator(&self, pubkey: &str, now: UtcSecs) -> bool {
        let state = self.effective_state(now);
        state.is_owner_key(pubkey)
            || self.passports.get(pubkey).is_some_and(|p| p.is_moderator() && state.verify_passport(p, now).is_ok())
    }

    /// Moderadores conhecidos: (pubkey, permissões, expira em)
    pub fn moderators(&self, now: UtcSecs) -> Vec<(String, Vec<PassportPermission>, Option<UtcSecs>)> {
        let state = self.effective_state(now);
        self.passports
            .values()
            .filter(|p| p.is_moderator() && state.verify_passport(p, now).is_ok())
            .map(|p| (p.body.holder.clone(), p.body.permissions.clone(), p.effective_expires_at()))
            .collect()
    }

    /// Descarta ações provisórias que já entraram na cadeia ou que o estado atual recusa
    fn prune_pending(&mut self, now: UtcSecs) {
        let effective = self.effective_state(now);
        let chain = self.chain.state();
        self.pending.retain(|id, _| effective.applied_actions.contains(id) && !chain.applied_actions.contains(id));
    }

    /// Anexa um carimbo ao objeto com este hash (ação provisória, meu passaporte ou conhecido)
    fn attach_stamp(&mut self, imprint: &[u8; 32], stamp: &TimestampAttestation) -> bool {
        let mut changed = false;
        for pending in self.pending.values_mut() {
            if &pending.action.imprint() == imprint {
                changed |= pending.action.add_stamp(stamp.clone());
            }
        }
        if let Some(mine) = self.my_passport.as_mut() {
            changed |= mine.add_stamp_to_link(imprint, stamp);
        }
        for passport in self.passports.values_mut() {
            changed |= passport.add_stamp_to_link(imprint, stamp);
        }
        changed
    }

    /// Mensagens com a cadeia a partir de `from_height` e as ações provisórias
    fn sync_messages(&self, from_height: u64) -> Vec<ServerMessage> {
        let blocks = self.chain.blocks().iter().skip(from_height as usize).cloned().collect::<Vec<_>>();
        let mut out: Vec<ServerMessage> = blocks
            .chunks(BLOCKS_PER_MESSAGE)
            .map(|chunk| ServerMessage::Blocks { server_id: self.server_id.clone(), blocks: chunk.to_vec() })
            .collect();
        out.extend(self.pending.values().map(|p| ServerMessage::Action(p.action.clone())));
        out
    }
}

/// O que aconteceu ao processar uma mensagem de servidor recebida da rede
#[derive(Debug)]
pub enum ServerEvent {
    /// A cadeia avançou (ou foi trocada num fork)
    ChainUpdated { server_id: String, name: String, height: u64 },
    /// Fork detectado na altura `height`; `replaced` = este nó trocou de ramo
    Fork { server_id: String, height: u64, replaced: bool },
    /// Faltam blocos: publicar um `ChainRequest` a partir de `from_height`
    NeedBlocks { server_id: String, from_height: u64 },
    /// Ação de moderador válida aceita como provisória
    ActionAccepted { server_id: String, action: ModAction },
    /// Ações provisórias desfeitas porque a cadeia nova as invalidou
    ActionsUndone { server_id: String, count: usize },
    /// Responder publicando estas mensagens no tópico de controle
    Reply { server_id: String, messages: Vec<ServerMessage> },
    /// Carimbo anexado a algo que este nó guarda
    StampAttached { server_id: String },
    /// Mensagem descartada (inválida, antiga ou de servidor que não acompanhamos)
    Ignored(String),
}

#[derive(Serialize, Deserialize)]
struct StoredServer {
    server_id: String,
    blocks: Vec<Block>,
    pending: Vec<PendingAction>,
    #[serde(default)]
    passports: Vec<ServerPassport>,
}

/// Uma linha do histórico de alterações (para exibição)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub height: u64,
    pub timestamp: UtcSecs,
    pub description: String,
}

/// Servidores que este nó acompanha, com persistência opcional em disco:
/// - `<dir>/<id>.server.json`: blocos da cadeia, ações provisórias e passaportes conhecidos
/// - `<dir>/<id>.owner-key.json`: chave do servidor (só no nó do dono; nunca é apagada)
/// - `<dir>/<id>.passport.json`: passaporte deste nó
#[derive(Default)]
pub struct ServerRegistry {
    dir: Option<PathBuf>,
    servers: BTreeMap<String, KnownServer>,
}

impl ServerRegistry {
    /// Registro sem persistência (testes)
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Carrega os servidores salvos em `dir` (cria a pasta se não existir).
    /// Blocos são revalidados ao carregar: um arquivo adulterado perde a cadeia a partir do ponto alterado.
    pub fn load(dir: impl AsRef<Path>, now: UtcSecs) -> Result<Self, CommunityError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let mut registry = Self { dir: Some(dir.clone()), servers: BTreeMap::new() };

        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            let Some(file) = path.file_name().and_then(|n| n.to_str()) else { continue };
            let Some(id) = file.strip_suffix(".server.json") else { continue };
            if !is_valid_server_id(id) {
                continue;
            }
            let Ok(stored) = serde_json::from_slice::<StoredServer>(&std::fs::read(&path)?) else {
                tracing::warn!("Servidor salvo ilegível (formato antigo?): {:?}", path);
                continue;
            };
            let mut server = KnownServer::new(id);
            for block in stored.blocks {
                if server.chain.try_append(block) != AppendResult::Appended {
                    break;
                }
            }
            for pending in stored.pending {
                server.pending.insert(pending.action.id(), pending);
            }
            server.prune_pending(now);
            let key_path = dir.join(format!("{}.owner-key.json", id));
            if key_path.exists() {
                let key = UserIdentity::load_or_create(&key_path)?;
                if key.public_key_hex() == id {
                    server.owner_key = Some(key);
                }
            }
            for passport in stored.passports {
                server.passports.insert(passport.body.holder.clone(), passport);
            }
            let passport_path = dir.join(format!("{}.passport.json", id));
            if passport_path.exists() {
                if let Ok(passport) = serde_json::from_slice::<ServerPassport>(&std::fs::read(&passport_path)?) {
                    server.my_passport = Some(passport);
                }
            }
            registry.servers.insert(id.to_string(), server);
        }
        Ok(registry)
    }

    pub fn get(&self, server_id: &str) -> Option<&KnownServer> {
        self.servers.get(server_id)
    }

    pub fn get_mut(&mut self, server_id: &str) -> Option<&mut KnownServer> {
        self.servers.get_mut(server_id)
    }

    pub fn list(&self) -> impl Iterator<Item = &KnownServer> {
        self.servers.values()
    }

    /// Procura por id completo, prefixo do id (4+ caracteres) ou nome (sem diferenciar maiúsculas)
    pub fn find(&self, query: &str) -> Option<&KnownServer> {
        self.servers.get(query).or_else(|| {
            self.servers
                .values()
                .find(|s| (query.len() >= 4 && s.server_id.starts_with(query)) || s.name().eq_ignore_ascii_case(query))
        })
    }

    /// Cria um servidor com chave própria e a política de tempo sugerida (FreeTSA). Este nó vira o
    /// dono, e `owner_pubkey` (a identidade pessoal de quem cria) recebe um passaporte vitalício.
    pub fn create(&mut self, name: &str, owner_pubkey: &str, now: UtcSecs) -> Result<String, CommunityError> {
        self.create_with_policy(name, owner_pubkey, TimestampPolicy::default(), now)
    }

    pub fn create_with_policy(&mut self, name: &str, owner_pubkey: &str, policy: TimestampPolicy, now: UtcSecs) -> Result<String, CommunityError> {
        let key = UserIdentity::generate_with_nick(name);
        let id = key.public_key_hex();
        if let Some(dir) = &self.dir {
            key.save_to(dir.join(format!("{}.owner-key.json", id)))?;
        }
        let mut server = KnownServer::new(&id);
        server.chain.append_own(
            &key,
            now,
            vec![Entry::Genesis {
                name: name.to_string(),
                owner: owner_pubkey.to_string(),
                channels: default_channels(),
                closed: false,
                passport_validity_secs: DEFAULT_PASSPORT_VALIDITY_SECS,
                renewal_window_secs: DEFAULT_RENEWAL_WINDOW_SECS,
                timestamp_policy: policy,
            }],
        );
        let passport = ServerPassport::issue_root(&key, owner_pubkey, PassportPermission::all(), now, None);
        server.set_my_passport(passport);
        server.owner_key = Some(key);
        self.servers.insert(id.clone(), server);
        self.persist(&id)?;
        Ok(id)
    }

    /// Passa a acompanhar um servidor pelo id. Retorna `false` se já acompanhava.
    /// A cadeia chega depois, de algum membro online.
    pub fn join(&mut self, server_id: &str) -> Result<bool, CommunityError> {
        if !is_valid_server_id(server_id) {
            return Err(CommunityError::InvalidServerId);
        }
        if self.servers.contains_key(server_id) {
            return Ok(false);
        }
        self.servers.insert(server_id.to_string(), KnownServer::new(server_id));
        self.persist(server_id)?;
        Ok(true)
    }

    /// Deixa de acompanhar o servidor. A chave de dono, se existir, é mantida em disco.
    pub fn leave(&mut self, server_id: &str) -> bool {
        let removed = self.servers.remove(server_id).is_some();
        if let (true, Some(dir)) = (removed, &self.dir) {
            let _ = std::fs::remove_file(dir.join(format!("{}.server.json", server_id)));
            let _ = std::fs::remove_file(dir.join(format!("{}.passport.json", server_id)));
        }
        removed
    }

    /// Recebe um passaporte destinado a este nó. Sem a cadeia ainda (servidor privado recém-aceito),
    /// guarda depois de conferir só a assinatura da cadeia; ele acompanha o `ChainRequest`.
    pub fn accept_my_passport(&mut self, server_id: &str, me: &str, passport: &ServerPassport, now: UtcSecs) -> bool {
        let Some(server) = self.servers.get_mut(server_id) else { return false };
        if passport.body.holder != me {
            return false;
        }
        let ok = if server.has_chain() {
            server.effective_state(now).verify_passport(passport, now).is_ok()
        } else {
            passport.verify_at(server_id, now).is_ok()
        };
        if !ok || server.my_passport.as_ref() == Some(passport) {
            return false;
        }
        server.set_my_passport(passport.clone());
        let _ = self.persist(server_id);
        true
    }

    /// Processa uma mensagem do tópico de controle. `from_pubkey` é quem publicou (do PeerId),
    /// usado para não entregar a cadeia de um servidor privado a quem está fora dele.
    pub fn handle_message(&mut self, message: ServerMessage, from_pubkey: Option<&str>, now: UtcSecs) -> Vec<ServerEvent> {
        match message {
            ServerMessage::Blocks { server_id, mut blocks } => {
                let Some(server) = self.servers.get_mut(&server_id) else {
                    return vec![ServerEvent::Ignored("servidor não acompanhado".into())];
                };
                blocks.sort_by_key(|b| b.body.height);
                let before = server.chain.head().map(Block::hash);
                let mut events = Vec::new();
                for block in blocks {
                    match server.chain.try_append(block) {
                        AppendResult::Appended | AppendResult::Duplicate => {}
                        AppendResult::Gap { need_from } => {
                            events.push(ServerEvent::NeedBlocks { server_id: server_id.clone(), from_height: need_from });
                            break;
                        }
                        AppendResult::Fork { height, replaced } => {
                            events.push(ServerEvent::Fork { server_id: server_id.clone(), height, replaced })
                        }
                        AppendResult::Invalid(reason) => {
                            events.push(ServerEvent::Ignored(format!("bloco recusado: {}", reason)));
                            break;
                        }
                    }
                }
                if server.chain.head().map(Block::hash) != before {
                    let pending_before = server.pending.len();
                    server.prune_pending(now);
                    let undone = pending_before - server.pending.len();
                    let height = server.chain.head().map_or(0, |b| b.body.height);
                    events.push(ServerEvent::ChainUpdated { server_id: server_id.clone(), name: server.name(), height });
                    if undone > 0 {
                        events.push(ServerEvent::ActionsUndone { server_id: server_id.clone(), count: undone });
                    }
                    let _ = self.persist(&server_id);
                }
                events
            }
            ServerMessage::ChainRequest { server_id, from_height, passport } => {
                let Some(server) = self.servers.get_mut(&server_id).filter(|s| s.has_chain()) else {
                    return vec![ServerEvent::Ignored("sem cadeia para responder".into())];
                };
                if let Some(p) = &passport {
                    server.learn_passport(p, now);
                }
                let state = server.effective_state(now);
                if state.closed && !from_pubkey.is_some_and(|pk| server.is_allowed_with_passport(pk, passport.as_ref(), now)) {
                    return vec![ServerEvent::Ignored("servidor privado: pedido de quem não tem passaporte".into())];
                }
                vec![ServerEvent::Reply { messages: server.sync_messages(from_height), server_id }]
            }
            ServerMessage::Stamp { server_id, imprint, stamp } => {
                let Some(server) = self.servers.get_mut(&server_id) else {
                    return vec![ServerEvent::Ignored("servidor não acompanhado".into())];
                };
                let Some(imprint) = parse_imprint(&imprint) else {
                    return vec![ServerEvent::Ignored("carimbo com hash inválido".into())];
                };
                if server.attach_stamp(&imprint, &stamp) {
                    let _ = self.persist(&server_id);
                    return vec![ServerEvent::StampAttached { server_id }];
                }
                Vec::new()
            }
            ServerMessage::KeyPackage { .. }
            | ServerMessage::Commit { .. }
            | ServerMessage::Welcome { .. }
            | ServerMessage::GroupAnnounce { .. }
            | ServerMessage::PassportOffer { .. }
            | ServerMessage::FlattenRequest { .. }
            | ServerMessage::AccessRequest { .. }
            | ServerMessage::StampRequest { .. } => {
                vec![ServerEvent::Ignored("mensagem do grupo cifrado, passaporte ou carimbo (tratada pelo runtime)".into())]
            }
            ServerMessage::Action(action) => {
                let server_id = action.body.server_id.clone();
                let Some(server) = self.servers.get_mut(&server_id) else {
                    return vec![ServerEvent::Ignored("servidor não acompanhado".into())];
                };
                if !server.has_chain() {
                    return vec![ServerEvent::Ignored("cadeia ainda não sincronizada".into())];
                }
                let id = action.id();
                if let Some(known) = server.pending.get_mut(&id) {
                    // Mesma ação com carimbos novos
                    let mut changed = false;
                    for stamp in &action.stamps {
                        changed |= known.action.add_stamp(stamp.clone());
                    }
                    if changed {
                        let _ = self.persist(&server_id);
                    }
                    return vec![ServerEvent::Ignored("ação já conhecida".into())];
                }
                server.learn_passport(&action.passport, now);
                match server.effective_state(now).check_mod_action(&action, now) {
                    Ok(()) => {
                        server.pending.insert(id, PendingAction { action: action.clone(), seen_at: now });
                        let _ = self.persist(&server_id);
                        vec![ServerEvent::ActionAccepted { server_id, action }]
                    }
                    Err(rejection) => vec![ServerEvent::Ignored(format!("ação recusada: {}", rejection))],
                }
            }
        }
    }

    /// Pedido da cadeia a partir do que este nó já tem (com o passaporte, para servidores privados)
    pub fn chain_request(&self, server_id: &str) -> Option<ServerMessage> {
        let server = self.servers.get(server_id)?;
        Some(ServerMessage::ChainRequest {
            server_id: server_id.to_string(),
            from_height: server.chain.blocks().len() as u64,
            passport: server.my_passport.clone(),
        })
    }

    /// Tudo que este nó sabe do servidor, para entregar a quem acabou de entrar no tópico
    pub fn snapshot(&self, server_id: &str) -> Vec<ServerMessage> {
        self.servers.get(server_id).filter(|s| s.has_chain()).map(|s| s.sync_messages(0)).unwrap_or_default()
    }

    // ---------- Passaportes ----------

    /// Emite um passaporte para `holder`: pela Chave do Servidor (se este nó é o dono) ou como
    /// subordinado do passaporte deste nó. A validade padrão vem da política do servidor.
    pub fn issue_passport(
        &self,
        server_id: &str,
        issuer: &UserIdentity,
        holder: &str,
        permissions: Vec<PassportPermission>,
        duration: Option<u64>,
        now: UtcSecs,
    ) -> Result<ServerPassport, CommunityError> {
        let server = self.servers.get(server_id).ok_or(CommunityError::UnknownServer)?;
        if !server.has_chain() {
            return Err(CommunityError::NoChainYet);
        }
        let validity = server.chain.state().passport_validity_secs.max(3600);
        if let Some(key) = server.owner_key() {
            return Ok(ServerPassport::issue_root(key, holder, permissions, now, duration.map(|d| now + d)));
        }
        let mine = server.my_passport().ok_or(CommunityError::NoPassport)?;
        server.effective_state(now).verify_passport(mine, now)?;
        Ok(mine.issue_subordinate(issuer, holder, permissions, now, now + duration.unwrap_or(validity))?)
    }

    /// Pedido de acesso de `requester`. Em servidor público, quem pode emitir passaporte de membro
    /// responde com um passaporte novo — que não fura um ban em vigor (a janela o invalida, e a
    /// Chave do Servidor não emite automaticamente para quem está banido).
    pub fn answer_access_request(&self, server_id: &str, issuer: &UserIdentity, requester: &str, now: UtcSecs) -> Option<ServerMessage> {
        let server = self.servers.get(server_id).filter(|s| s.has_chain())?;
        let state = server.effective_state(now);
        if state.closed || state.is_banned(requester, now) {
            return None;
        }
        // Já conhecemos um passaporte válido dele: o pedido repetido indica que a oferta anterior
        // não chegou (pedido feito antes de ter a cadeia, ou perda no gossip). Reenvia o mesmo.
        if server.is_allowed(requester, now) {
            let passport = server.passport_of(requester)?.clone();
            return Some(ServerMessage::PassportOffer { server_id: server_id.to_string(), target: requester.to_string(), passport });
        }
        let can_issue = server.is_owner() || server.my_passport().is_some_and(|p| p.allows(PassportPermission::IssueMember));
        if !can_issue {
            return None;
        }
        let validity = state.passport_validity_secs.max(3600);
        let passport = self.issue_passport(server_id, issuer, requester, PassportPermission::member(), Some(validity), now).ok()?;
        state.verify_passport(&passport, now).ok()?;
        Some(ServerMessage::PassportOffer { server_id: server_id.to_string(), target: requester.to_string(), passport })
    }

    /// Anexa um carimbo a quem tiver esse hash (usado quando o próprio nó obtém o carimbo)
    pub fn attach_stamp(&mut self, server_id: &str, imprint: &[u8; 32], stamp: &TimestampAttestation) -> bool {
        let changed = self.servers.get_mut(server_id).is_some_and(|s| s.attach_stamp(imprint, stamp));
        if changed {
            let _ = self.persist(server_id);
        }
        changed
    }

    /// Carimbo de testemunha deste nó para `imprint`, se ele participa do servidor
    pub fn witness_stamp(&self, server_id: &str, witness: &UserIdentity, imprint: &str, nonce: &str, now: UtcSecs) -> Option<ServerMessage> {
        let server = self.servers.get(server_id).filter(|s| s.has_chain())?;
        let digest = parse_imprint(imprint)?;
        let passport = server.my_passport()?;
        server.effective_state(now).verify_passport(passport, now).ok()?;
        let token = PeerTimestampToken::issue(witness, passport, &digest, nonce, now);
        Some(ServerMessage::Stamp {
            server_id: server_id.to_string(),
            imprint: imprint.to_string(),
            stamp: TimestampAttestation::Peer(Box::new(token)),
        })
    }

    // ---------- Operações do dono (assinam blocos com a chave do servidor) ----------

    fn owner_append(&mut self, server_id: &str, now: UtcSecs, entries: Vec<Entry>) -> Result<ServerMessage, CommunityError> {
        let server = self.servers.get_mut(server_id).ok_or(CommunityError::UnknownServer)?;
        let key = server.owner_key.clone().ok_or(CommunityError::NotOwner)?;
        if !server.has_chain() {
            return Err(CommunityError::NoChainYet);
        }
        let block = server.chain.append_own(&key, now, entries);
        server.prune_pending(now);
        self.persist(server_id)?;
        Ok(ServerMessage::Blocks { server_id: server_id.to_string(), blocks: vec![block] })
    }

    pub fn add_channel(&mut self, server_id: &str, name: &str, kind: ChannelType, now: UtcSecs) -> Result<ServerMessage, CommunityError> {
        if self.get(server_id).is_some_and(|s| s.channels().iter().any(|c| c.name == name)) {
            return Err(CommunityError::ChannelExists);
        }
        self.owner_append(server_id, now, vec![Entry::AddChannel(Channel { name: name.to_string(), channel_type: kind })])
    }

    pub fn remove_channel(&mut self, server_id: &str, name: &str, now: UtcSecs) -> Result<ServerMessage, CommunityError> {
        if !self.get(server_id).is_some_and(|s| s.channels().iter().any(|c| c.name == name)) {
            return Err(CommunityError::UnknownChannel);
        }
        self.owner_append(server_id, now, vec![Entry::RemoveChannel(name.to_string())])
    }

    pub fn set_closed(&mut self, server_id: &str, closed: bool, now: UtcSecs) -> Result<ServerMessage, CommunityError> {
        self.owner_append(server_id, now, vec![Entry::SetClosed(closed)])
    }

    pub fn set_passport_policy(
        &mut self,
        server_id: &str,
        validity_secs: u64,
        renewal_window_secs: u64,
        now: UtcSecs,
    ) -> Result<ServerMessage, CommunityError> {
        self.owner_append(server_id, now, vec![Entry::SetPassportPolicy { validity_secs, renewal_window_secs }])
    }

    /// Acrescenta (ou substitui pelo nome) uma autoridade de tempo na política do servidor
    pub fn add_tsa(&mut self, server_id: &str, tsa: TrustedTsa, now: UtcSecs) -> Result<ServerMessage, CommunityError> {
        if spki::SubjectPublicKeyInfoRef::try_from(tsa.spki_der.as_slice()).is_err() {
            return Err(CommunityError::InvalidTsa("chave pública (SubjectPublicKeyInfo DER) ilegível".into()));
        }
        let server = self.servers.get(server_id).ok_or(CommunityError::UnknownServer)?;
        let mut policy = server.chain.state().timestamp_policy.clone();
        policy.tsas.retain(|t| t.name != tsa.name);
        policy.tsas.push(tsa);
        self.owner_append(server_id, now, vec![Entry::SetTimestampPolicy(policy)])
    }

    pub fn remove_tsa(&mut self, server_id: &str, name: &str, now: UtcSecs) -> Result<ServerMessage, CommunityError> {
        let server = self.servers.get(server_id).ok_or(CommunityError::UnknownServer)?;
        let mut policy = server.chain.state().timestamp_policy.clone();
        let before = policy.tsas.len();
        policy.tsas.retain(|t| !t.name.eq_ignore_ascii_case(name));
        if policy.tsas.len() == before {
            return Err(CommunityError::InvalidTsa(format!("'{}' não está na política", name)));
        }
        self.owner_append(server_id, now, vec![Entry::SetTimestampPolicy(policy)])
    }

    /// Revoga todos os passaportes de moderação conhecidos de uma pubkey (dono)
    pub fn remove_moderator(&mut self, server_id: &str, pubkey: &str, now: UtcSecs) -> Result<ServerMessage, CommunityError> {
        let server = self.servers.get(server_id).ok_or(CommunityError::UnknownServer)?;
        let entries: Vec<Entry> = server
            .passports
            .get(pubkey)
            .filter(|p| p.is_moderator() && !server.chain.state().revoked.contains(&p.body.serial))
            .map(|p| Entry::RevokePassport { serial: p.body.serial.clone() })
            .into_iter()
            .collect();
        if entries.is_empty() {
            return Err(CommunityError::NotModerator);
        }
        self.owner_append(server_id, now, entries)
    }

    /// Manutenção do dono, chamada periodicamente enquanto ele está online: inclui na cadeia as
    /// ações provisórias válidas dos moderadores (consolidação). Retorna o bloco a publicar.
    pub fn owner_maintenance(&mut self, server_id: &str, now: UtcSecs) -> Option<ServerMessage> {
        let server = self.servers.get(server_id)?;
        server.owner_key.as_ref()?;
        if !server.has_chain() {
            return None;
        }
        let effective = server.effective_state(now);
        let mut pending: Vec<&PendingAction> =
            server.pending.values().filter(|p| effective.applied_actions.contains(&p.action.id())).collect();
        pending.sort_by(|a, b| (a.action.body.created_at, a.action.id()).cmp(&(b.action.body.created_at, b.action.id())));
        let entries: Vec<Entry> = pending.into_iter().map(|p| Entry::IncludeModAction(p.action.clone())).collect();
        if entries.is_empty() {
            return None;
        }
        self.owner_append(server_id, now, entries).ok()
    }

    // ---------- Moderação (dono assina blocos; moderador assina ações) ----------

    /// Bane, desbane ou revoga. O dono grava direto num bloco; um moderador cria uma ação assinada
    /// com o próprio passaporte, válida na hora como provisória.
    pub fn moderate(
        &mut self,
        server_id: &str,
        personal: &UserIdentity,
        kind: ModKind,
        target: &str,
        reason: &str,
        now: UtcSecs,
    ) -> Result<ServerMessage, CommunityError> {
        let server = self.servers.get(server_id).ok_or(CommunityError::UnknownServer)?;
        if !server.has_chain() {
            return Err(CommunityError::NoChainYet);
        }
        if server.is_owner() {
            let entry = match kind {
                ModKind::Ban { until } => Entry::Ban { target: target.to_string(), until, reason: reason.to_string() },
                ModKind::Unban => Entry::Unban { target: target.to_string() },
                ModKind::Revoke { serial } => Entry::RevokePassport { serial },
            };
            return self.owner_append(server_id, now, vec![entry]);
        }
        let passport = server.my_passport().cloned().ok_or(CommunityError::NoPassport)?;
        if !passport.allows(kind.permission()) {
            return Err(CommunityError::NotModerator);
        }
        let action = ModAction::create(personal, &passport, kind, target, reason, now);
        let state = server.effective_state(now);
        state.check_mod_action(&action, now).map_err(CommunityError::Rejected)?;
        let server = self.servers.get_mut(server_id).expect("verificado acima");
        server.pending.insert(action.id(), PendingAction { action: action.clone(), seen_at: now });
        self.persist(server_id)?;
        Ok(ServerMessage::Action(action))
    }

    /// Histórico de alterações da cadeia, do mais antigo ao mais novo
    pub fn history(&self, server_id: &str) -> Vec<HistoryEntry> {
        let Some(server) = self.servers.get(server_id) else { return Vec::new() };
        server
            .chain
            .blocks()
            .iter()
            .map(|block| HistoryEntry {
                height: block.body.height,
                timestamp: block.body.timestamp,
                description: block.body.entries.iter().map(describe_entry).collect::<Vec<_>>().join("; "),
            })
            .collect()
    }

    pub fn persist(&self, server_id: &str) -> Result<(), CommunityError> {
        let (Some(dir), Some(server)) = (&self.dir, self.servers.get(server_id)) else { return Ok(()) };
        let stored = StoredServer {
            server_id: server_id.to_string(),
            blocks: server.chain.blocks().to_vec(),
            pending: server.pending.values().cloned().collect(),
            passports: server.passports.values().cloned().collect(),
        };
        std::fs::write(dir.join(format!("{}.server.json", server_id)), serde_json::to_vec_pretty(&stored)?)?;
        if let Some(passport) = &server.my_passport {
            std::fs::write(dir.join(format!("{}.passport.json", server_id)), serde_json::to_vec_pretty(passport)?)?;
        }
        Ok(())
    }
}

/// Hash de carimbo em hex (64 caracteres) para bytes
pub fn parse_imprint(hex: &str) -> Option<[u8; 32]> {
    hex_decode_32(hex).ok()
}

/// Descrição curta de uma alteração (pubkeys abreviadas)
fn describe_entry(entry: &Entry) -> String {
    match entry {
        Entry::Genesis { name, owner, closed, .. } => {
            format!("criado '{}' por {}{}", name, short_id(owner), if *closed { " (privado)" } else { "" })
        }
        Entry::SetOwner(owner) => format!("posse transferida para {}", short_id(owner)),
        Entry::SetName(name) => format!("renomeado para '{}'", name),
        Entry::AddChannel(c) => format!("canal {}{} criado", if c.channel_type == ChannelType::Voice { "🔊 " } else { "#" }, c.name),
        Entry::RemoveChannel(name) => format!("canal {} removido", name),
        Entry::SetClosed(true) => "servidor privado (passaporte emitido por moderador)".into(),
        Entry::SetClosed(false) => "servidor público (passaporte automático)".into(),
        Entry::SetPassportPolicy { validity_secs, renewal_window_secs } => format!(
            "passaportes: validade {}, renovação nos últimos {}",
            format_duration(Some(*validity_secs)),
            format_duration(Some(*renewal_window_secs))
        ),
        Entry::SetTimestampPolicy(policy) => format!(
            "autoridades de tempo: {}",
            if policy.tsas.is_empty() { "só testemunhas da rede".to_string() } else { policy.tsas.iter().map(|t| t.name.as_str()).collect::<Vec<_>>().join(", ") }
        ),
        Entry::RevokePassport { serial } => format!("passaporte {} revogado", serial),
        Entry::Ban { target, until, .. } => format!(
            "dono baniu {} ({})",
            short_id(target),
            until.map_or("permanente".to_string(), |u| format!("até {}", u))
        ),
        Entry::Unban { target } => format!("dono desbaniu {}", short_id(target)),
        Entry::IncludeModAction(action) => {
            let verb = match &action.body.kind {
                ModKind::Ban { .. } => "baniu".to_string(),
                ModKind::Unban => "desfez o ban de".to_string(),
                ModKind::Revoke { serial } => format!("revogou o passaporte {} de", serial),
            };
            format!("moderador {} {} {}", short_id(action.actor()), verb, short_id(&action.body.target))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_800_000_000;
    /// Identidade pessoal de quem cria os servidores nos testes
    const OWNER: &str = "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e";

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("anarchord_test_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Entrega mensagens de um registro a outro, como a rede faria
    fn deliver(to: &mut ServerRegistry, messages: Vec<ServerMessage>, from: Option<&str>, now: u64) -> Vec<ServerEvent> {
        messages.into_iter().flat_map(|m| to.handle_message(m, from, now)).collect()
    }

    /// Dono cria o servidor; membro entra e sincroniza a cadeia
    fn owner_and_member() -> (ServerRegistry, ServerRegistry, String) {
        let mut owner = ServerRegistry::in_memory();
        let id = owner.create("Rust Guild", OWNER, T0).unwrap();
        let mut member = ServerRegistry::in_memory();
        member.join(&id).unwrap();
        let request = member.chain_request(&id).unwrap();
        let reply = owner.handle_message(request, None, T0);
        let ServerEvent::Reply { messages, .. } = &reply[0] else { panic!("{:?}", reply) };
        deliver(&mut member, messages.clone(), None, T0);
        (owner, member, id)
    }

    fn pk(id: &UserIdentity) -> String {
        id.public_key_hex()
    }

    /// Dono emite passaporte de moderador e o registro `to` passa a ser desse moderador
    fn make_moderator(owner: &ServerRegistry, to: &mut ServerRegistry, id: &str, who: &UserIdentity, at: u64) -> ServerPassport {
        let passport = owner.issue_passport(id, &UserIdentity::generate(), &pk(who), PassportPermission::default_moderator(), None, at).unwrap();
        assert!(to.accept_my_passport(id, &pk(who), &passport, at));
        passport
    }

    #[test]
    fn test_topics_keep_lobby_compatible_and_namespace_servers() {
        assert_eq!(channel_topic(&Space::Lobby, "geral"), "p2p-anarchord/channel/geral");
        assert_eq!(voice_topic(&Space::Lobby, "sala"), "p2p-anarchord/voice/sala");
        let id = "ab".repeat(32);
        let space = Space::Server(id.clone());
        assert_eq!(channel_topic(&space, "geral"), format!("p2p-anarchord/server/{}/channel/geral", id));
        assert_eq!(parse_server_control_topic(&server_control_topic(&id)), Some(id.as_str()));
        assert_eq!(parse_server_control_topic(&channel_topic(&space, "geral")), None);
        assert_eq!(parse_server_content_topic(&channel_topic(&space, "geral")), Some(id.as_str()));
        assert_eq!(parse_server_channel_topic(&channel_topic(&space, "geral")), Some((id.as_str(), "geral")));
        assert_eq!(parse_server_channel_topic(&voice_topic(&space, "voz")), None, "voz não é canal de texto");
        assert_eq!(parse_server_channel_topic(&channel_topic(&Space::Lobby, "geral")), None);
        assert_eq!(parse_server_content_topic(&voice_topic(&space, "voz")), Some(id.as_str()));
        assert_eq!(parse_server_content_topic(&screen_topic(&space)), Some(id.as_str()));
        assert_eq!(parse_server_content_topic(&server_control_topic(&id)), None);
        assert_eq!(parse_server_content_topic(&channel_topic(&Space::Lobby, "geral")), None);
        assert_eq!(screen_topic(&Space::Lobby), "p2p-anarchord/screens");
        assert_eq!(screen_stream_topic(&Space::Lobby, "screen:ab12cd34"), "p2p-anarchord/screens/screen:ab12cd34");
        assert_eq!(parse_server_content_topic(&screen_stream_topic(&space, "screen:ab12cd34")), Some(id.as_str()), "quadros de servidor são cifrados");
    }

    #[test]
    fn test_member_syncs_chain_and_policy_from_owner() {
        let (_owner, member, id) = owner_and_member();
        let server = member.get(&id).unwrap();
        assert!(server.has_chain());
        assert!(!server.is_owner());
        assert_eq!(server.name(), "Rust Guild");
        assert_eq!(server.default_text_channel().as_deref(), Some("geral"));
        assert!(server.is_allowed(&id, T0), "a chave do servidor sempre participa");
        assert_eq!(server.chain().state().timestamp_policy.tsas[0].name, "FreeTSA", "FreeTSA sugerida na criação");
    }

    #[test]
    fn test_participation_requires_passport() {
        let (owner, mut member, id) = owner_and_member();
        let guest = UserIdentity::generate();
        assert!(!member.get(&id).unwrap().is_allowed(&pk(&guest), T0), "sem passaporte não participa, nem em servidor público");
        let passport = owner.issue_passport(&id, &UserIdentity::generate(), &pk(&guest), PassportPermission::member(), None, T0).unwrap();
        // Os membros conhecem o passaporte quando ele chega no KeyPackage de entrada (ou no Welcome)
        assert!(member.get_mut(&id).unwrap().learn_passport(&passport, T0));
        assert!(member.get(&id).unwrap().is_allowed(&pk(&guest), T0 + 1));
    }

    #[test]
    fn test_same_second_passports_converge_to_wider_regardless_of_order() {
        let (owner, mut member, id) = owner_and_member();
        let guest = UserIdentity::generate();
        let issuer = UserIdentity::generate();
        let basic = owner.issue_passport(&id, &issuer, &pk(&guest), PassportPermission::member(), None, T0).unwrap();
        let moderator = owner.issue_passport(&id, &issuer, &pk(&guest), PassportPermission::default_moderator(), None, T0).unwrap();
        let mut stamped = basic.clone();
        stamped.stamps.push(TimestampAttestation::Rfc3161 { tsa: "x".into(), token_der: vec![] });
        stamped.stamps.push(TimestampAttestation::Rfc3161 { tsa: "x".into(), token_der: vec![] });

        // Membro chega atrasado (com carimbos) depois do moderador emitido no mesmo segundo
        let server = member.get_mut(&id).unwrap();
        assert!(server.learn_passport(&basic, T0));
        assert!(server.learn_passport(&moderator, T0), "moderador amplia o membro do mesmo segundo");
        assert!(!server.learn_passport(&stamped, T0), "membro atrasado não rebaixa o moderador");
        assert!(server.passport_of(&pk(&guest)).unwrap().is_moderator());
    }

    #[test]
    fn test_access_request_resends_known_passport() {
        let (mut owner, _member, id) = owner_and_member();
        let guest = UserIdentity::generate();
        let issuer = UserIdentity::generate();
        let Some(ServerMessage::PassportOffer { passport: first, .. }) = owner.answer_access_request(&id, &issuer, &pk(&guest), T0) else { panic!() };
        owner.get_mut(&id).unwrap().learn_passport(&first, T0);
        // A oferta se perdeu (pedido antes de ter a cadeia): o pedido repetido recebe o mesmo passaporte
        let Some(ServerMessage::PassportOffer { passport: again, .. }) = owner.answer_access_request(&id, &issuer, &pk(&guest), T0 + 5) else {
            panic!("pedido repetido deve reenviar a oferta")
        };
        assert_eq!(again.body.serial, first.body.serial);
    }

    #[test]
    fn test_gap_requests_missing_blocks() {
        let (mut owner, mut member, id) = owner_and_member();
        owner.add_channel(&id, "a", ChannelType::Text, T0 + 1).unwrap();
        let latest = owner.add_channel(&id, "b", ChannelType::Text, T0 + 2).unwrap();
        let events = deliver(&mut member, vec![latest], None, T0 + 3);
        assert!(matches!(events.as_slice(), [ServerEvent::NeedBlocks { from_height: 1, .. }]), "{:?}", events);

        let request = member.chain_request(&id).unwrap();
        let ServerEvent::Reply { messages, .. } = owner.handle_message(request, None, T0 + 3).remove(0) else { panic!() };
        deliver(&mut member, messages, None, T0 + 3);
        assert!(member.get(&id).unwrap().has_channel("b", ChannelType::Text));
    }

    #[test]
    fn test_moderator_action_is_provisional_then_consolidated() {
        let (mut owner, mut member, id) = owner_and_member();
        let moderator = UserIdentity::generate();
        let spammer = pk(&UserIdentity::generate());
        make_moderator(&owner, &mut member, &id, &moderator, T0 + 10);

        let action = member.moderate(&id, &moderator, ModKind::Ban { until: None }, &spammer, "spam", T0 + 20).unwrap();
        assert!(member.get(&id).unwrap().is_banned(&spammer, T0 + 20), "vale na hora como provisória");

        let events = deliver(&mut owner, vec![action], None, T0 + 21);
        assert!(matches!(events.as_slice(), [ServerEvent::ActionAccepted { .. }]), "{:?}", events);
        assert!(owner.get(&id).unwrap().is_banned(&spammer, T0 + 21));

        let block = owner.owner_maintenance(&id, T0 + 30).expect("deveria consolidar");
        assert!(owner.get(&id).unwrap().chain().state().is_banned(&spammer, T0 + 30), "agora definitivo");
        assert_eq!(owner.get(&id).unwrap().pending_actions().count(), 0);
        deliver(&mut member, vec![block], None, T0 + 31);
        assert_eq!(member.get(&id).unwrap().pending_actions().count(), 0, "incluída na cadeia: sai da fila");
        assert!(owner.owner_maintenance(&id, T0 + 40).is_none(), "nada mais a fazer");
    }

    /// Moderador revogado: ações provisórias posteriores dele são desfeitas quando a revogação chega
    #[test]
    fn test_revocation_undoes_later_provisional_actions() {
        let (mut owner, mut member, id) = owner_and_member();
        let rogue = UserIdentity::generate();
        let victim = pk(&UserIdentity::generate());
        let mut rogue_registry = ServerRegistry::in_memory();
        rogue_registry.join(&id).unwrap();
        deliver(&mut rogue_registry, owner.snapshot(&id), None, T0 + 1);
        let rogue_p = make_moderator(&owner, &mut rogue_registry, &id, &rogue, T0 + 10);
        owner.get_mut(&id).unwrap().learn_passport(&rogue_p, T0 + 10);

        let revoke = owner.remove_moderator(&id, &pk(&rogue), T0 + 30).unwrap();
        // O moderador age depois da revogação, sem saber dela
        let action = rogue_registry.moderate(&id, &rogue, ModKind::Ban { until: None }, &victim, "abuso", T0 + 40).unwrap();
        deliver(&mut member, vec![action], None, T0 + 41);
        assert!(member.get(&id).unwrap().is_banned(&victim, T0 + 41), "o membro foi influenciado");
        let events = deliver(&mut member, vec![revoke], None, T0 + 50);
        assert!(events.iter().any(|e| matches!(e, ServerEvent::ActionsUndone { count: 1, .. })), "{:?}", events);
        assert!(!member.get(&id).unwrap().is_banned(&victim, T0 + 401), "ação desfeita");
    }

    #[test]
    fn test_only_owner_changes_configuration_and_member_cannot_moderate() {
        let (owner, mut member, id) = owner_and_member();
        assert!(matches!(member.add_channel(&id, "x", ChannelType::Text, T0), Err(CommunityError::NotOwner)));
        let nobody = UserIdentity::generate();
        let result = member.moderate(&id, &nobody, ModKind::Ban { until: None }, &"cd".repeat(32), "", T0);
        assert!(matches!(result, Err(CommunityError::NoPassport)));
        let plain = owner.issue_passport(&id, &UserIdentity::generate(), &pk(&nobody), PassportPermission::member(), None, T0).unwrap();
        member.accept_my_passport(&id, &pk(&nobody), &plain, T0);
        let result = member.moderate(&id, &nobody, ModKind::Ban { until: None }, &"cd".repeat(32), "", T0);
        assert!(matches!(result, Err(CommunityError::NotModerator)));
    }

    #[test]
    fn test_moderator_cannot_ban_owner_or_issuer() {
        let (owner, mut member, id) = owner_and_member();
        let moderator = UserIdentity::generate();
        make_moderator(&owner, &mut member, &id, &moderator, T0);
        let result = member.moderate(&id, &moderator, ModKind::Ban { until: None }, OWNER, "", T0 + 1);
        assert!(matches!(result, Err(CommunityError::Rejected(Rejection::ProtectedTarget))));
        let result = member.moderate(&id, &moderator, ModKind::Ban { until: None }, &id, "", T0 + 1);
        assert!(matches!(result, Err(CommunityError::Rejected(Rejection::ProtectedTarget))));
    }

    #[test]
    fn test_public_server_answers_access_requests_but_not_for_banned() {
        let (mut owner, _member, id) = owner_and_member();
        let guest = pk(&UserIdentity::generate());
        let issuer = UserIdentity::generate();
        let Some(ServerMessage::PassportOffer { passport, .. }) = owner.answer_access_request(&id, &issuer, &guest, T0 + 1) else { panic!() };
        assert_eq!(passport.body.expires_at, Some(T0 + 1 + 7 * 86_400), "passaporte automático usa a validade da política");
        assert!(owner.get(&id).unwrap().chain().state().verify_passport(&passport, T0 + 1).is_ok());

        let banned = pk(&UserIdentity::generate());
        owner.moderate(&id, &issuer, ModKind::Ban { until: Some(T0 + 3600) }, &banned, "", T0 + 2).unwrap();
        assert!(owner.answer_access_request(&id, &issuer, &banned, T0 + 3).is_none(), "ban em vigor: sem passaporte automático");
        assert!(owner.answer_access_request(&id, &issuer, &banned, T0 + 3600).is_some(), "prazo acabou: volta a receber");

        owner.set_closed(&id, true, T0 + 4).unwrap();
        assert!(owner.answer_access_request(&id, &issuer, &pk(&UserIdentity::generate()), T0 + 5).is_none(), "privado: só emissão manual");
    }

    #[test]
    fn test_moderator_without_issue_member_does_not_answer_access_requests() {
        let (owner, mut member, id) = owner_and_member();
        let plain = UserIdentity::generate();
        let passport = owner.issue_passport(&id, &UserIdentity::generate(), &pk(&plain), PassportPermission::member(), None, T0).unwrap();
        member.accept_my_passport(&id, &pk(&plain), &passport, T0);
        assert!(member.answer_access_request(&id, &plain, &pk(&UserIdentity::generate()), T0 + 1).is_none());
        let moderator = UserIdentity::generate();
        make_moderator(&owner, &mut member, &id, &moderator, T0);
        assert!(member.answer_access_request(&id, &moderator, &pk(&UserIdentity::generate()), T0 + 1).is_some());
    }

    #[test]
    fn test_private_server_does_not_serve_outsiders() {
        let (mut owner, _member, id) = owner_and_member();
        owner.set_closed(&id, true, T0 + 1).unwrap();
        let insider = UserIdentity::generate();
        let passport = owner.issue_passport(&id, &UserIdentity::generate(), &pk(&insider), PassportPermission::member(), None, T0 + 2).unwrap();

        let outsider = pk(&UserIdentity::generate());
        let request = ServerMessage::ChainRequest { server_id: id.clone(), from_height: 0, passport: None };
        assert!(matches!(owner.handle_message(request.clone(), Some(&outsider), T0 + 3)[0], ServerEvent::Ignored(_)));
        assert!(matches!(owner.handle_message(request, None, T0 + 3)[0], ServerEvent::Ignored(_)), "sem autor conhecido");
        let with_passport = ServerMessage::ChainRequest { server_id: id.clone(), from_height: 0, passport: Some(passport) };
        assert!(matches!(owner.handle_message(with_passport, Some(&pk(&insider)), T0 + 3)[0], ServerEvent::Reply { .. }));
    }

    #[test]
    fn test_member_without_chain_keeps_offered_passport_for_chain_request() {
        let (owner, _member, id) = owner_and_member();
        let newcomer = UserIdentity::generate();
        let mut fresh = ServerRegistry::in_memory();
        fresh.join(&id).unwrap();
        let passport = owner.issue_passport(&id, &UserIdentity::generate(), &pk(&newcomer), PassportPermission::member(), None, T0).unwrap();
        assert!(fresh.accept_my_passport(&id, &pk(&newcomer), &passport, T0), "aceito só pela assinatura");
        let Some(ServerMessage::ChainRequest { passport: Some(sent), .. }) = fresh.chain_request(&id) else { panic!() };
        assert_eq!(sent, passport);
    }

    #[test]
    fn test_stamp_attaches_to_pending_action_and_witness_stamp() {
        let (owner, mut member, id) = owner_and_member();
        let moderator = UserIdentity::generate();
        make_moderator(&owner, &mut member, &id, &moderator, T0);
        let ServerMessage::Action(action) = member.moderate(&id, &moderator, ModKind::Ban { until: None }, &pk(&UserIdentity::generate()), "", T0 + 1).unwrap() else { panic!() };

        let imprint = timestamp::hex(&action.imprint());
        let witness = UserIdentity::generate();
        let mut witness_registry = ServerRegistry::in_memory();
        witness_registry.join(&id).unwrap();
        deliver(&mut witness_registry, owner.snapshot(&id), None, T0);
        assert!(witness_registry.witness_stamp(&id, &witness, &imprint, "n", T0 + 2).is_none(), "sem passaporte não testemunha");
        let wp = owner.issue_passport(&id, &UserIdentity::generate(), &pk(&witness), PassportPermission::member(), None, T0).unwrap();
        witness_registry.accept_my_passport(&id, &pk(&witness), &wp, T0);
        let stamp = witness_registry.witness_stamp(&id, &witness, &imprint, "n", T0 + 2).unwrap();
        let events = deliver(&mut member, vec![stamp], Some(&pk(&witness)), T0 + 3);
        assert!(matches!(events.as_slice(), [ServerEvent::StampAttached { .. }]), "{:?}", events);
        assert_eq!(member.get(&id).unwrap().pending_actions().next().unwrap().stamps.len(), 1);
    }

    #[test]
    fn test_owner_temporary_ban_from_registry() {
        let (mut owner, mut member, id) = owner_and_member();
        let target = pk(&UserIdentity::generate());
        let block = owner.moderate(&id, &UserIdentity::generate(), ModKind::Ban { until: Some(T0 + 3600) }, &target, "1h", T0).unwrap();
        deliver(&mut member, vec![block], None, T0 + 1);
        assert!(member.get(&id).unwrap().is_banned(&target, T0 + 10));
        assert!(!member.get(&id).unwrap().is_banned(&target, T0 + 3600));
    }

    #[test]
    fn test_tsa_policy_is_server_configuration() {
        let (mut owner, mut member, id) = owner_and_member();
        let local = timestamp::test_tsa::LocalTsa::new().trusted("Minha TSA");
        let block = owner.add_tsa(&id, local, T0 + 1).unwrap();
        deliver(&mut member, vec![block], None, T0 + 1);
        let names: Vec<String> = member.get(&id).unwrap().chain().state().timestamp_policy.tsas.iter().map(|t| t.name.clone()).collect();
        assert_eq!(names, vec!["FreeTSA".to_string(), "Minha TSA".to_string()]);
        owner.remove_tsa(&id, "freetsa", T0 + 2).unwrap();
        assert_eq!(owner.get(&id).unwrap().chain().state().timestamp_policy.tsas.len(), 1);
        let bad = TrustedTsa { name: "x".into(), url: "http://x".into(), spki_der: vec![1, 2, 3] };
        assert!(matches!(owner.add_tsa(&id, bad, T0 + 3), Err(CommunityError::InvalidTsa(_))));
    }

    #[test]
    fn test_history_lists_every_change() {
        let (mut owner, _member, id) = owner_and_member();
        owner.add_channel(&id, "jogos", ChannelType::Text, T0 + 1).unwrap();
        owner.set_closed(&id, true, T0 + 2).unwrap();
        let history = owner.history(&id);
        assert_eq!(history.len(), 3);
        assert!(history[0].description.contains("criado 'Rust Guild'"));
        assert!(history[1].description.contains("#jogos"));
        assert_eq!(history[2].description, "servidor privado (passaporte emitido por moderador)");
        assert!(history.windows(2).all(|w| w[0].timestamp <= w[1].timestamp));
    }

    #[test]
    fn test_persistence_restores_chain_ownership_pending_and_passports() {
        let dir = temp_dir("chain_persist");
        let moderator = UserIdentity::generate();
        let target = pk(&UserIdentity::generate());
        let id = {
            let mut reg = ServerRegistry::load(&dir, T0).unwrap();
            let id = reg.create("Persistente", OWNER, T0).unwrap();
            reg.add_channel(&id, "jogos", ChannelType::Voice, T0 + 1).unwrap();
            id
        };
        {
            // Outro nó (o do moderador) com a mesma pasta: ação provisória fica salva
            let mut reg = ServerRegistry::load(&dir, T0 + 3).unwrap();
            let passport = reg.issue_passport(&id, &UserIdentity::generate(), &pk(&moderator), PassportPermission::default_moderator(), None, T0 + 2).unwrap();
            let server = reg.servers.get_mut(&id).unwrap();
            server.owner_key = None; // simula o registro do moderador
            server.set_my_passport(passport);
            reg.moderate(&id, &moderator, ModKind::Ban { until: None }, &target, "", T0 + 4).unwrap();
        }
        let reg = ServerRegistry::load(&dir, T0 + 5).unwrap();
        let server = reg.get(&id).unwrap();
        assert!(server.is_owner(), "chave de dono continua no disco");
        assert!(server.has_channel("jogos", ChannelType::Voice));
        assert_eq!(server.pending_actions().count(), 1);
        assert!(server.is_banned(&target, T0 + 5));
        assert!(server.passport_of(&pk(&moderator)).is_some(), "passaportes conhecidos persistem");
        assert_eq!(reg.find("persistente").map(|s| s.server_id.clone()), Some(id.clone()));

        let mut reg = reg;
        assert!(reg.leave(&id));
        assert!(dir.join(format!("{}.owner-key.json", id)).exists(), "sair nunca apaga a chave");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tampered_file_loses_chain_from_altered_block() {
        let dir = temp_dir("chain_tamper");
        let id = {
            let mut reg = ServerRegistry::load(&dir, T0).unwrap();
            let id = reg.create("Original", OWNER, T0).unwrap();
            reg.add_channel(&id, "segredo", ChannelType::Text, T0 + 1).unwrap();
            id
        };
        let path = dir.join(format!("{}.server.json", id));
        let text = std::fs::read_to_string(&path).unwrap().replace("segredo", "alterado");
        std::fs::write(&path, text).unwrap();
        let reg = ServerRegistry::load(&dir, T0 + 2).unwrap();
        let server = reg.get(&id).unwrap();
        assert_eq!(server.chain().blocks().len(), 1, "bloco adulterado e seguintes descartados");
        assert!(!server.has_channel("alterado", ChannelType::Text));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
