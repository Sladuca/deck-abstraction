use barnett_smart_card_protocol::{discrete_log_cards, BarnettSmartProtocol};

use ark_ec::ProjectiveCurve;
use ark_ff::ToBytes;
use ark_std::{rand::Rng, One};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError};
use borsh::{BorshSerialize, BorshDeserialize};
use proof_essentials::homomorphic_encryption::el_gamal::Plaintext;
use proof_essentials::utils::permutation::Permutation;
use proof_essentials::utils::rand::sample_vector;
use proof_essentials::zkp::proofs::{chaum_pedersen_dl_equality, schnorr_identification};
use ark_std::io::{Write, Read};
use std::iter::Iterator;
use thiserror::Error;
use rand::rngs::StdRng;

#[cfg(feature = "wasm")]
extern crate wasm_bindgen;

#[cfg(feature = "wasm")]
extern crate wee_alloc;
#[cfg(feature = "wasm")]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// Choose elliptic curve setting
type Curve = ark_bn254::G1Projective;
type Scalar = ark_bn254::Fr;

// Instantiate concrete type for our card protocol
type CardProtocol<'a> = discrete_log_cards::DLCards<'a, Curve>;

#[repr(transparent)]
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "npm", wasm_bindgen)]
pub struct CardParameters(pub discrete_log_cards::Parameters<Curve>);

impl CardParameters {
    fn num_cards(&self) -> usize {
        self.0.num_cards()
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey(pub discrete_log_cards::PublicKey<Curve>);

#[repr(transparent)]
#[derive(Copy, Clone, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "npm", wasm_bindgen)]
pub struct SecretKey(pub discrete_log_cards::PlayerSecretKey<Curve>);

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "npm", wasm_bindgen)]
pub struct OpenedCard(pub discrete_log_cards::Card<Curve>);

#[repr(transparent)]
#[derive(Copy, Clone, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
#[cfg_attr(feature = "npm", wasm_bindgen)]
pub struct MaskedCard(pub discrete_log_cards::MaskedCard<Curve>);

#[repr(transparent)]
#[derive(Copy, Clone, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "npm", wasm_bindgen)]
pub struct RevealToken(pub discrete_log_cards::RevealToken<Curve>);

#[repr(transparent)]
#[derive(CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "npm", wasm_bindgen)]
pub struct ShuffleProof(pub discrete_log_cards::ZKProofShuffle<Curve>);

#[repr(transparent)]
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "npm", wasm_bindgen)]
pub struct KeyOwnershipProof(pub schnorr_identification::proof::Proof<Curve>);

#[repr(transparent)]
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "npm", wasm_bindgen)]
pub struct RemaskingProof(pub chaum_pedersen_dl_equality::proof::Proof<Curve>);

#[repr(transparent)]
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "npm", wasm_bindgen)]
pub struct MaskingProof(pub chaum_pedersen_dl_equality::proof::Proof<Curve>);

#[repr(transparent)]
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "npm", wasm_bindgen)]
pub struct RevealProof(pub chaum_pedersen_dl_equality::proof::Proof<Curve>);

macro_rules! impl_borsh_for_canonical_serialize {
    ($t:ident) => {
        impl borsh::ser::BorshSerialize for $t {
            fn serialize<W: borsh::maybestd::io::Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
                <$t as ark_serialize::CanonicalSerialize>::serialize(&self, writer).map_err(|_| borsh::maybestd::io::Error::new(borsh::maybestd::io::ErrorKind::Other, "Serialization failed"))
            }
        }

        impl borsh::de::BorshDeserialize for $t {
            fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
                let mut bytes = vec![];
                bytes.extend_from_slice(buf);
                let mut reader = borsh::maybestd::io::Cursor::new(bytes);
                let value = <$t as ark_serialize::CanonicalDeserialize>::deserialize(&mut reader).map_err(|_| borsh::maybestd::io::Error::new(borsh::maybestd::io::ErrorKind::InvalidData, "Deserialization failed"))?;
                *buf = &buf[reader.position() as usize..];
                Ok(value)
            }
        }
    };
}

impl_borsh_for_canonical_serialize!(CardParameters);
impl_borsh_for_canonical_serialize!(PublicKey);
impl_borsh_for_canonical_serialize!(SecretKey);
impl_borsh_for_canonical_serialize!(OpenedCard);
impl_borsh_for_canonical_serialize!(MaskedCard);
impl_borsh_for_canonical_serialize!(RevealToken);
impl_borsh_for_canonical_serialize!(ShuffleProof);
impl_borsh_for_canonical_serialize!(KeyOwnershipProof);
impl_borsh_for_canonical_serialize!(RemaskingProof);
impl_borsh_for_canonical_serialize!(MaskingProof);
impl_borsh_for_canonical_serialize!(RevealProof);


#[derive(Error, Debug, PartialEq)]
pub enum DeckError {
    #[error("No such card in hand")]
    CardNotFound,

    #[error("No such player in game")]
    PlayerNotFound,

    #[error("Invalid card")]
    InvalidCard,

    #[error("key aggregation failed")]
    KeyAggregationFailed,

    #[error("invalid masking proof")]
    InvalidMaskingProof,

    #[error("invalid remasking proof")]
    InvalidRemaskingProof,

    #[error("invalid shuffle proof")]
    InvalidShuffleProof,

    #[error("invalid reveal proof")]
    InvalidRevealProof,

    #[error("invalid reveal token")]
    InvalidRevealToken,

    #[error("missing reveal token")]
    MissingRevealToken,

    #[error("could not compute reveal token")]
    RevealTokenComputationFailed,

    #[error("no reveal token for opened card")]
    NoRevealTokenForOpenedCard,

    #[error("failed to mask card")]
    MaskingFailed,

    #[error("failed to shuffle deck")]
    ShuffleFailed,

    #[error("attempted to mask already-masked card. use remask instead")]
    MaskAlreadyMaskedCard,

    #[error("attempted to remask opened card. use mask instead")]
    RemaskOpenedCard,

    #[error("attempted to reveal opened card")]
    RevealOpenedCard,

    #[error("attempted to shuffle opened card")]
    ShuffleOpenedCard,

    #[error("submitted reveal tokens for wrong cards!")]
    WrongCardsRevealed,

    #[error("not your turn")]
    NotYourTurn,

    #[error("wrong op")]
    WrongOp,
}

#[derive(PartialEq, Clone, Copy, Eq, Debug, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "npm", wasm_bindgen)]
pub enum Suit {
    Club,
    Diamond,
    Heart,
    Spade,
}

impl Suit {
    const VALUES: [Self; 4] = [Self::Club, Self::Diamond, Self::Heart, Self::Spade];
}

#[derive(PartialEq, PartialOrd, Clone, Copy, Eq, Debug, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "npm", wasm_bindgen)]
pub enum Value {
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
    Eight,
    Nine,
    Ten,
    Jack,
    Queen,
    King,
    Ace,
}

impl Value {
    const VALUES: [Self; 13] = [
        Self::Two,
        Self::Three,
        Self::Four,
        Self::Five,
        Self::Six,
        Self::Seven,
        Self::Eight,
        Self::Nine,
        Self::Ten,
        Self::Jack,
        Self::Queen,
        Self::King,
        Self::Ace,
    ];
}

#[derive(PartialEq, Clone, Eq, Copy, Debug, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "npm", wasm_bindgen)]
pub struct CardValue {
    value: Value,
    suit: Suit,
}

impl CardValue {
    pub fn new(value: Value, suit: Suit) -> Self {
        Self { value, suit }
    }
}

#[derive(PartialEq, Clone, Copy, BorshSerialize, BorshDeserialize)]
pub enum Card {
    Opened(OpenedCard),
    Masked(MaskedCard),
}

impl Eq for Card {}

#[derive(Clone, BorshDeserialize, BorshSerialize)]
#[cfg_attr(feature = "npm", wasm_bindgen)]

pub struct CardMapping {
    pub(crate) mapping: Vec<(OpenedCard, CardValue)>,
}

impl CardMapping {
    fn get_value(&self, card: &OpenedCard) -> Option<CardValue> {
        self.mapping
            .iter()
            .find(|(c, _)| c == card)
            .map(|(_, v)| *v)
    }
}

#[cfg_attr(feature = "npm", wasm_bindgen)]
pub fn get_card_mapping() -> CardMapping {
    let mut card_mapping = Vec::new();
    let mut g = Curve::prime_subgroup_generator();
    for suit in Suit::VALUES.iter() {
        for value in Value::VALUES.iter() {
            let card_value = CardValue::new(*value, *suit);
            g = g.double();
            card_mapping.push((OpenedCard(Plaintext(g.into_affine())), card_value));
        }
    }

    CardMapping {
        mapping: card_mapping,
    }
}

#[derive(Clone)]
#[cfg_attr(feature = "npm", wasm_bindgen)]
pub struct PublicPlayersState<U: Clone + PartialEq + Eq + ToBytes + BorshSerialize + BorshDeserialize> {
    // player IDs, their associated public keys for the game, and ownership proofs for those keys to prevent rouge key attacks
    pub players: Vec<(PublicKey, KeyOwnershipProof, U)>,

    // the joint public key aggregated from each player's individual public keys
    pub joint_public_key: PublicKey,

    // the trusted setup parameters for the card protocol
    pub params: CardParameters,
}

/// a struct containing the public state of a deck.
/// this is the state that is intended to be stored on-chain
/// each player will also keep an instance of `PrivateDeckState` (see below).
/// Type `U` is a type representing a unique identifier for a player.
/// this can be a user's on-chain address, an off-chain username, a shielded pool's re-randomizable address, etc
#[derive(Clone)]
pub struct PublicDeckState<U: Clone + PartialEq + Eq + ToBytes + BorshSerialize + BorshDeserialize> {
    /// the players, joint PK, and trusted setup params
    pub players: PublicPlayersState<U>,

    /// the current state of the deck's cards as an array of masked cards
    pub cards: Vec<MaskedCard>,

    /// reveal_tokens[card_idx][player_idx]
    pub reveal_tokens: Vec<Vec<Option<RevealToken>>>,

    // current operation being performed. All players must go around in the correct order for the operation to succeed
    pub op: Option<DeckOp>,
    // idx of the player who's turn it is in the protocol
    pub turn: usize,
    // idx of the player who started the current operation
    pub start_turn: usize,

    pub card_mapping: CardMapping,
}

impl<U: Clone + PartialEq + Eq + ToBytes + BorshSerialize + BorshDeserialize> PublicPlayersState<U> {
    pub fn new(
        players: Vec<(PublicKey, KeyOwnershipProof, U)>,
        params: CardParameters,
    ) -> Result<Self, DeckError> {
        let players_inner = players.iter().cloned().map(|(a, b, c)| (a.0, b.0, c)).collect();
        let joint_public_key = CardProtocol::compute_aggregate_key(&params.0, &players_inner)
            .map_err(|_| DeckError::KeyAggregationFailed)?;
            
        Ok(Self {
            players,
            joint_public_key: PublicKey(joint_public_key),
            params,
        })
    }
}

#[derive(PartialEq, Eq, Clone)]
pub enum DeckOp {
    /// Shuffle the deck.
    /// Each player will apply their own shuffle and proof
    Shuffle,

    /// Deal a batch of cards given a list of `(player_idx, idx)` tuples indicates the card at `idx` should be dealt to the player at `player_idx`
    /// for each card, every player but the recipient will unmask the card. Then the recipient can unmask the card
    Deal(Vec<(usize, usize)>),

    /// Reeval a batch of cards from the deck to everyone
    Reveal(Vec<usize>),
}

pub fn deck_setup<R: Rng>(rng: &mut R) -> CardParameters {
    CardParameters(CardProtocol::setup(rng, 2, 26).unwrap())
}

#[cfg_attr(feature = "npm", wasm_bindgen)]
pub fn rng_from_seed(seed: &[u8; 32]) -> StdRng {
    use rand::SeedableRng;
    let rng = StdRng::from_seed(*seed);
    rng
}

// stuff that smart contract should do
impl<U: Clone + PartialEq + Eq + ToBytes + BorshSerialize + BorshDeserialize> PublicDeckState<U> {
    fn new(
        players: PublicPlayersState<U>,
        masked_cards: Vec<MaskedCard>,
        masking_proofs: Vec<MaskingProof>,
    ) -> Result<Self, DeckError> {
        assert_eq!(players.params.num_cards(), 52);

        
        let card_mapping = get_card_mapping();
        let plaintext_cards = (0..52)
            .map(|i| card_mapping.mapping[i].0)
            .collect::<Vec<_>>();

        for (plaintext, (ciphertext, masking_proof)) in plaintext_cards.iter().zip(masked_cards.iter().zip(masking_proofs.iter())) {
            CardProtocol::verify_mask(
                &players.params.0,
                &players.joint_public_key.0,
                &plaintext.0,
                &ciphertext.0,
                &masking_proof.0,
            )
            .map_err(|_| DeckError::InvalidMaskingProof)?;
        }

        let num_players = players.players.len();

        Ok(Self {
            players,
            cards: masked_cards,
            reveal_tokens: vec![vec![None; num_players]; 52],
            turn: 0,
            start_turn: 0,
            op: None,
            card_mapping,
        })
    }

    pub fn rotate_start_player(&mut self) {
        self.start_turn = self.start_turn + 1 % self.players.players.len();
    }

    pub fn set_op(&mut self, op: DeckOp) {
        self.op = Some(op);
    }

    pub fn shuffle(
        &mut self,
        calling_player_idx: usize,
        shuffled_deck: Vec<MaskedCard>,
        proof: ShuffleProof,
    ) -> Result<(), DeckError> {
        if self.op != Some(DeckOp::Shuffle) {
            return Err(DeckError::WrongOp);
        }
        if self.turn != calling_player_idx {
            return Err(DeckError::NotYourTurn);
        }

        let old_deck = self.cards.iter().cloned().map(|card| card.0).collect();
        let shuffled_deck = shuffled_deck.iter().cloned().map(|masked_card| masked_card.0).collect();
        CardProtocol::verify_shuffle(
            &self.players.params.0,
            &self.players.joint_public_key.0,
            &old_deck,
            &shuffled_deck,
            &proof.0,
        )
        .map_err(|_| DeckError::InvalidShuffleProof)?;

        self.cards = shuffled_deck.iter().cloned().map(MaskedCard).collect();
        self.turn = (self.turn + 1) % self.players.players.len();

        if self.turn == self.start_turn {
            self.op = None;
        }

        Ok(())
    }

    pub fn deal(
        &mut self,
        calling_player_idx: usize,
        reveals: Vec<(usize, RevealToken, RevealProof)>,
    ) -> Result<(), DeckError> {
        if let Some(DeckOp::Deal(ref instances)) = self.op {
            if self.turn != calling_player_idx {
                return Err(DeckError::NotYourTurn);
            }

            // check that the correct cards are being revealed
            let cards_should_reveal = instances
                .iter()
                .filter(|(player_idx, _)| *player_idx != calling_player_idx)
                .map(|(_, card_idx)| *card_idx);
            let cards_revealed = reveals.iter().map(|(card_idx, _, _)| *card_idx);

            if !cards_should_reveal
                .zip(cards_revealed)
                .all(|(should, did)| should == did)
            {
                return Err(DeckError::WrongCardsRevealed);
            }

            for (card_idx, token, proof) in reveals {
                CardProtocol::verify_reveal(
                    &self.players.params.0,
                    &self.players.players[calling_player_idx].0.0,
                    &token.0,
                    &self.cards[card_idx].0,
                    &proof.0,
                )
                .map_err(|_| DeckError::InvalidRevealProof)?;
                self.reveal_tokens[card_idx][calling_player_idx] = Some(token);
            }

            self.turn = (self.turn + 1) % self.players.players.len();
            if self.turn == self.start_turn {
                self.op = None;
            }

            Ok(())
        } else {
            Err(DeckError::WrongOp)
        }
    }

    #[cfg_attr(feature = "npm", wasm_bindgen)]
    pub fn reveal(
        &mut self,
        calling_player_idx: usize,
        reveals: Vec<(usize, RevealToken, RevealProof)>,
    ) -> Result<(), DeckError> {
        if let Some(DeckOp::Reveal(ref instances)) = self.op {
            if self.turn != calling_player_idx {
                return Err(DeckError::NotYourTurn);
            }

            // check that the correct cards are being revealed
            let cards_should_reveal = instances.iter().map(|card_idx| *card_idx);
            let cards_revealed = reveals.iter().map(|(card_idx, _, _)| *card_idx);

            if !cards_should_reveal
                .zip(cards_revealed)
                .all(|(should, did)| should == did)
            {
                return Err(DeckError::WrongCardsRevealed);
            }

            for (card_idx, token, proof) in reveals {
                CardProtocol::verify_reveal(
                    &self.players.params.0,
                    &self.players.players[calling_player_idx].0.0,
                    &token.0,
                    &self.cards[card_idx].0,
                    &proof.0,
                )
                .map_err(|_| DeckError::InvalidRevealProof)?;
                self.reveal_tokens[card_idx][calling_player_idx] = Some(token);
            }

            Ok(())
        } else {
            Err(DeckError::WrongOp)
        }
    }
}

#[cfg_attr(feature = "npm", wasm_bindgen)]
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct DeckPlayerState<U: Clone + PartialEq + Eq + ToBytes> {
    pub id: U,
    pub player_idx: usize,
    pub players: Vec<(PublicKey, U)>,
    pub joint_pk: PublicKey,
    pub sk: SecretKey,
    pub pk: PublicKey,
    pub key_ownership_proof: KeyOwnershipProof,
    pub cards: Vec<Card>,
    pub reveal_tokens: Vec<Vec<Option<(RevealToken, RevealProof)>>>,
    pub params: CardParameters,
    pub card_mapping: CardMapping,
}

#[cfg_attr(feature = "npm", wasm_bindgen)]
#[derive(Clone)]
pub struct Keys {
    pub sk: SecretKey,
    pub pk: PublicKey,
    pub key_ownership_proof: KeyOwnershipProof,
}

#[cfg_attr(feature = "npm", wasm_bindgen)]
#[derive(Clone)]
pub struct RevealTokenForCardWithProof {
    pub card_idx: usize,
    pub token: RevealToken,
    pub proof: RevealProof,
}

#[cfg_attr(feature = "npm", wasm_bindgen)]
#[derive(Clone)]
pub struct RevealTokenForCard {
    pub card_idx: usize,
    pub token: RevealToken,
    pub proof: RevealProof,
}

#[cfg_attr(feature = "npm", wasm_bindgen)]
#[derive(Clone)]
pub struct MaskedDeckWithProofs {
    pub cards: Vec<MaskedCard>,
    pub proofs: Vec<MaskingProof>,
}

#[cfg_attr(feature = "npm", wasm_bindgen)]
pub struct ShuffledDeckWithProof{
    pub cards: Vec<MaskedCard>,
    pub proof: ShuffleProof,
}

#[cfg_attr(feature = "npm", wasm_bindgen)]
pub fn keygen<U: Clone + PartialEq + Eq + ToBytes + BorshSerialize + BorshDeserialize>(
    params: &CardParameters,
    id: U,
) -> Keys {
    let mut rng = rand::thread_rng();
    let (pk, sk) = CardProtocol::player_keygen(&mut rng, &params.0).unwrap();
    let mut player_id_bytes = Vec::new();
    id.write(&mut player_id_bytes).unwrap();
    let key_ownership_proof =
        CardProtocol::prove_key_ownership(&mut rng, &params.0, &pk, &sk, &player_id_bytes).unwrap();
    Keys {
        sk: SecretKey(sk),
        pk: PublicKey(pk),
        key_ownership_proof: KeyOwnershipProof(key_ownership_proof)
    }
}


// stuff that players do client-side
impl<U: Clone + PartialEq + Eq + ToBytes + BorshSerialize + BorshDeserialize> DeckPlayerState<U> {
    #[cfg_attr(feature = "npm", wasm_bindgen(constructor))]
    pub fn new(
        id: U,
        pk: PublicKey,
        sk: SecretKey,
        key_ownership_proof: KeyOwnershipProof,
        joint_pk: PublicKey,
        params: CardParameters,
        player_ids: Vec<U>,
        player_pks: Vec<PublicKey>
    ) -> Self {
        assert_eq!(params.num_cards(), 52);

        let players = player_ids.into_iter().zip(player_pks).map(|(id, pk)| (pk, id)).collect::<Vec<_>>();

        let player_idx = players
            .iter()
            .position(|(_, player_id)| player_id == &id)
            .unwrap();
        let num_players = players.len();

        let card_mapping = get_card_mapping();
        let cards = (0..52)
            .map(|i| Card::Opened(card_mapping.mapping[i].0))
            .collect::<Vec<_>>();

        // todo figure out why arkworks isn't implementing clone...
        let reveal_tokens = (0..params.num_cards())
            .map(|_| (0..num_players).map(|_| None).collect())
            .collect();

        DeckPlayerState {
            id,
            player_idx,
            players,
            joint_pk,
            sk,
            pk,
            key_ownership_proof,
            reveal_tokens,
            params,
            cards,
            card_mapping,
        }
    }

    #[cfg_attr(feature = "npm", wasm_bindgen)]
    pub fn observe_deck(&mut self, cards: Vec<Card>) {
        self.cards = cards;
    }

    #[cfg_attr(feature = "npm", wasm_bindgen)]
    pub fn observe_masked_deck(&mut self, cards: Vec<MaskedCard>) {
        self.cards = cards.into_iter().map(Card::Masked).collect();
    }

    #[cfg_attr(feature = "npm", wasm_bindgen)]
    fn clear_reveal_tokens(&mut self) {
        for reveal_tokens in self.reveal_tokens.iter_mut() {
            for reveal_token in reveal_tokens.iter_mut() {
                *reveal_token = None;
            }
        }
    }

    #[cfg_attr(feature = "npm", wasm_bindgen)]
    pub fn observe_reveal_token(
        &mut self,
        player_idx: usize,
        token: &RevealTokenForCardWithProof 
    ) {
        let RevealTokenForCardWithProof { card_idx, token, proof } = token;
        self.reveal_tokens[*card_idx][player_idx] = Some((token.clone(), proof.clone()));
    }

    #[cfg_attr(feature = "npm", wasm_bindgen)]
    pub fn observe_reveal_tokens(
        &mut self,
        player_indices: &[usize],
        tokens: &[RevealTokenForCardWithProof]
    ) {
        for (player_idx, token) in player_indices.iter().zip(tokens.iter()) {
            self.observe_reveal_token(*player_idx, token)
        }
    }

    pub fn compute_reveal_token(
        &self,
        card: &MaskedCard,
    ) -> Result<(RevealToken, RevealProof), DeckError> {
        let mut rng = rand::thread_rng();
        let (token, proof) = CardProtocol::compute_reveal_token(&mut rng, &self.params.0, &self.sk.0, &self.pk.0, &card.0).map_err(|_| DeckError::RevealTokenComputationFailed)?;
        Ok((RevealToken(token), RevealProof(proof)))
    }

    #[cfg_attr(feature = "npm", wasm_bindgen)]
    pub fn view(
        &mut self,
        card_idx: usize,
    ) -> Result<CardValue, DeckError> {
        let mut rng = rand::thread_rng();
        match self.cards[card_idx] {
            Card::Masked(ref masked_card) => {
                let own_reveal_token = self.compute_reveal_token(masked_card)?;
                self.reveal_tokens[card_idx][self.player_idx] = Some(own_reveal_token);

                // check that all of the reveal tokens are Some
                if self.reveal_tokens[card_idx]
                    .iter()
                    .any(|reveal_token| reveal_token.is_none())
                {
                    return Err(DeckError::MissingRevealToken);
                }

                let unmasking_key = self.reveal_tokens[card_idx]
                    .iter()
                    .map(|token| token.as_ref().cloned().unwrap())
                    .enumerate()
                    .map(|(i, (token, proof))| {
                        (token.0, proof.0, self.players[i].0.0.clone())
                    })
                    .collect::<Vec<_>>();

                let unmasked_card = CardProtocol::unmask(&self.params.0, &unmasking_key, &masked_card.0)
                    .map_err(|_| DeckError::InvalidRevealProof)?;
                self.cards[card_idx] = Card::Opened(OpenedCard(unmasked_card));

                let value = self
                    .card_mapping
                    .get_value(&OpenedCard(unmasked_card))
                    .ok_or(DeckError::CardNotFound)?;

                Ok(value)
            }
            Card::Opened(_) => Err(DeckError::RevealOpenedCard),
        }
    }

    #[cfg_attr(feature = "npm", wasm_bindgen)]
    pub fn init(&mut self) -> Result<MaskedDeckWithProofs, DeckError> {
        let mut rng = rand::thread_rng();
        let mut masked_cards = Vec::new();
        let mut masking_proofs = Vec::new();
        for card in self.cards.iter_mut() {
            match card {
                Card::Opened(card) => {
                    let (masked_card, masking_proof) =
                        CardProtocol::mask(&mut rng, &self.params.0, &self.joint_pk.0, &card.0, &Scalar::one())
                            .map_err(|_| DeckError::MaskingFailed)?;
                    masked_cards.push(MaskedCard(masked_card));
                    masking_proofs.push(MaskingProof(masking_proof));
                },
                Card::Masked(_) => return Err(DeckError::MaskAlreadyMaskedCard)
            }
        }

        Ok(MaskedDeckWithProofs { cards: masked_cards, proofs: masking_proofs } )
    }

    #[cfg_attr(feature = "npm", wasm_bindgen)]
    pub fn shuffle(
        &mut self,
    ) -> Result<ShuffledDeckWithProof, DeckError> {
        // check to make sure cards have already been masked
        if self.cards.iter().any(|card| matches!(card, Card::Opened(_))) {
            return Err(DeckError::ShuffleOpenedCard);
        }
        

        let cards= self
            .cards
            .iter()
            .map(|card| match card {
                Card::Masked(masked_card) => masked_card.0.clone(),
                Card::Opened(_) => unreachable!(),
            })
            .collect::<Vec<_>>();

        let mut rng = rand::thread_rng();
        let permutation = Permutation::new(&mut rng, self.params.num_cards());
        let masking_factors: Vec<Scalar> = sample_vector(&mut rng, self.params.num_cards());
        let (shuffled_cards, shuffle_proof) = CardProtocol::shuffle_and_remask(
            &mut rng,
            &self.params.0,
            &self.joint_pk.0,
            &cards,
            &masking_factors,
            &permutation,
        ).map_err(|_| DeckError::ShuffleFailed)?;

        let shuffled_cards = shuffled_cards 
            .iter()
            .map(|masked_card| MaskedCard(masked_card.clone()))
            .collect::<Vec<_>>();

        self.cards = shuffled_cards
            .iter()
            .map(|masked_card| Card::Masked(masked_card.clone()))
            .collect();

       
        Ok(ShuffledDeckWithProof { cards: shuffled_cards, proof: ShuffleProof(shuffle_proof) })
    }

    #[cfg_attr(feature = "npm", wasm_bindgen)]
    pub fn deal(
        &mut self,
        // (player_idx, card_idx)
        instances: &[(usize, usize)],
    ) -> Result<Vec<RevealTokenForCardWithProof>, DeckError> {
        let mut reveal_tokens = Vec::new();
        for &(_, card_idx) in instances.iter().filter(|(player_idx, _)| *player_idx != self.player_idx) {
            let card = match self.cards[card_idx] {
                Card::Masked(ref masked_card) => masked_card,
                Card::Opened(_) => return Err(DeckError::RevealOpenedCard),
            };

            let (token, proof)= self.compute_reveal_token(card)?;
            reveal_tokens.push(RevealTokenForCardWithProof {
                card_idx,
                token,
                proof,
            });
        }

        Ok(reveal_tokens)
    }

    #[cfg_attr(feature = "npm", wasm_bindgen)]
    pub fn reveal(
        &mut self,
        indices: &[usize]
    ) -> Result<Vec<RevealTokenForCardWithProof>, DeckError> {
        let mut reveals = Vec::new();
        for &card_idx in indices {
            match self.cards[card_idx] {
                Card::Masked(ref card) =>{
                    match self.reveal_tokens[card_idx][self.player_idx].as_ref().cloned() {
                        Some((reveal_token, reveal_proof)) => {
                            reveals.push(
                                RevealTokenForCardWithProof {
                                    card_idx,
                                    token: reveal_token,
                                    proof: reveal_proof,
                                }
                            );
                        },
                        None => {
                            let (reveal_token, reveal_proof) = self.compute_reveal_token(card)?;
                            reveals.push(
                                RevealTokenForCardWithProof {
                                    card_idx,
                                    token: reveal_token,
                                    proof: reveal_proof,
                                }
                            );
                        }
                    }
                },
                Card::Opened(_) => {
                    if matches!(self.reveal_tokens[card_idx][self.player_idx], None) {
                        return Err(DeckError::NoRevealTokenForOpenedCard)
                    }

                    let (reveal_token , reveal_proof) = self.reveal_tokens[card_idx][self.player_idx].as_ref().cloned().unwrap();
                    reveals.push(
                        RevealTokenForCardWithProof {
                            card_idx,
                            token: reveal_token,
                            proof: reveal_proof,
                        }
                    );
                }
            }
        }

        Ok(reveals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round() {
        const NUM_PLAYERS: usize = 6;
        const NUM_ROUNDS: usize = 1;
        let mut rng = rand::thread_rng();
        let params = deck_setup(&mut rng);

        // setup public player state
        let mut player_keys = Vec::new();
        let mut player_pubs = Vec::new();
        for player_idx in 0..NUM_PLAYERS {
            let id = player_idx.to_be_bytes();
            let Keys { sk, pk, key_ownership_proof } = keygen(&params, id);
            player_keys.push((pk, sk, key_ownership_proof.clone(), id));
            player_pubs.push((pk, key_ownership_proof, id));
        }
        let pub_players_state  = PublicPlayersState::new(player_pubs.clone(), params.clone()).unwrap();

        // setup player state
        let player_ids = player_pubs.iter().cloned().map(|(_, _, id)| id).collect::<Vec<_>>();
        let player_pks = player_pubs.into_iter().map(|(pk, _, _)| pk).collect::<Vec<_>>();
        let mut players = (0..NUM_PLAYERS)
            .map(|player_idx| {
                let (pk, sk, key_ownership_proof, id) = player_keys[player_idx].clone();
                DeckPlayerState::new(
                    id,
                    pk,
                    sk,
                    key_ownership_proof,
                    pub_players_state.joint_public_key,
                    params.clone(),
                    player_ids.clone(),
                    player_pks.clone()
                )
            })
            .collect::<Vec<_>>();
      
            
        // play the game
        for _ in 0..NUM_ROUNDS {
            // someone instantiates a new deck
            let MaskedDeckWithProofs { cards: deck, proofs: masking_proofs} = players[0].init().unwrap();
            let mut pub_deck_state = PublicDeckState::new(pub_players_state.clone(), deck.clone(), masking_proofs).unwrap();

            // each player observes the deck
            players.iter_mut().for_each(|player| {
                player.observe_masked_deck(deck.clone());
            });

            // each player shuffles the deck
            pub_deck_state.set_op(DeckOp::Shuffle);
            for _ in 0..NUM_PLAYERS {
                let shuffling_player = pub_deck_state.turn;
                let ShuffledDeckWithProof { cards: shuffled_deck, proof: shuffle_proof } = players[shuffling_player].shuffle().unwrap();
                pub_deck_state.shuffle(shuffling_player, shuffled_deck.clone(), shuffle_proof).unwrap();

                // everyone observes the (re)-shuffled deck
                players.iter_mut().for_each(|player| {
                    player.observe_masked_deck(shuffled_deck.clone());
                });
            }

            // deal every player a card
            let deals = (0..NUM_PLAYERS).map(|i| (i, i)).collect::<Vec<_>>();
            pub_deck_state.set_op(DeckOp::Deal(deals.clone()));
            for _ in 0..NUM_PLAYERS {
                let player = pub_deck_state.turn;
                let reveals = players[player].deal(&deals).unwrap();

                let tuples = reveals.iter().cloned().map(|x| (x.card_idx, x.token, x.proof)).collect();
                pub_deck_state.deal(player, tuples).unwrap();

                // everyone observes the reveal tokens shared in the process
                players.iter_mut().enumerate().filter(|(i, _)| *i != player).for_each(|(_, p)| {
                    p.observe_reveal_tokens(&vec![player; reveals.len()], &reveals)
                });
            }

            // every player looks at their card
            let player_cards = (0..NUM_PLAYERS).map(|i| players[i].view(i).unwrap());
            for (i, card) in player_cards.enumerate() {
                println!("player {} card: {:?}", i, card);
            }

            // everyone reveals their card
            let card_indices = (0..NUM_PLAYERS).collect::<Vec<_>>();
            for _ in 0..NUM_PLAYERS {
                let player = pub_deck_state.turn;
                let reveals = players[player].reveal(&card_indices).unwrap();

                // everyone observes the reveal tokesn shared in the process
                players.iter_mut().enumerate().filter(|(i, _)| *i != player).for_each(|(_, p)| {
                    p.observe_reveal_tokens(&vec![player; reveals.len()], &reveals)
                });
            }

            // everyone clears their reveal tokens at the end of the round
            players.iter_mut().for_each(|p| {
                p.clear_reveal_tokens();
            });
        }
        

    }
}
