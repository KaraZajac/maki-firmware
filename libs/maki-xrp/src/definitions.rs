//! The XRP Ledger's fields and transaction types, as its binary format numbers them: made by
//! `tests/fixtures/make.mjs` from the binary codec's own definitions (ripple-binary-codec 2.11.0's
//! definitions.json, xrpl 5.3.0's). Don't edit it: make it again.

/// A field a transaction must have.
pub const REQUIRED: u8 = 0;
/// A field a transaction may have.
pub const OPTIONAL: u8 = 1;
/// A field a transaction may have, but not with its default value (an empty path set).
pub const DEFAULT: u8 = 2;

/// Every field the ledger knows, by its id (its type's code, then its own, a byte each), in
/// order: its name, and whether a signature covers it (none covers a signature).
pub const FIELDS: &[(u16, &str, bool)] = &[
    (0x0101, "LedgerEntryType", true),
    (0x0102, "TransactionType", true),
    (0x0103, "SignerWeight", true),
    (0x0104, "TransferFee", true),
    (0x0105, "TradingFee", true),
    (0x0106, "DiscountedFee", true),
    (0x0110, "Version", true),
    (0x0115, "LedgerFixType", true),
    (0x0116, "ManagementFeeRate", true),
    (0x0201, "NetworkID", true),
    (0x0202, "Flags", true),
    (0x0203, "SourceTag", true),
    (0x0204, "Sequence", true),
    (0x0205, "PreviousTxnLgrSeq", true),
    (0x0206, "LedgerSequence", true),
    (0x0207, "CloseTime", true),
    (0x0208, "ParentCloseTime", true),
    (0x0209, "SigningTime", true),
    (0x020a, "Expiration", true),
    (0x020b, "TransferRate", true),
    (0x020c, "WalletSize", true),
    (0x020d, "OwnerCount", true),
    (0x020e, "DestinationTag", true),
    (0x020f, "LastUpdateTime", true),
    (0x0210, "HighQualityIn", true),
    (0x0211, "HighQualityOut", true),
    (0x0212, "LowQualityIn", true),
    (0x0213, "LowQualityOut", true),
    (0x0214, "QualityIn", true),
    (0x0215, "QualityOut", true),
    (0x0216, "StampEscrow", true),
    (0x0217, "BondAmount", true),
    (0x0218, "LoadFee", true),
    (0x0219, "OfferSequence", true),
    (0x021a, "FirstLedgerSequence", true),
    (0x021b, "LastLedgerSequence", true),
    (0x021c, "TransactionIndex", true),
    (0x021d, "OperationLimit", true),
    (0x021e, "ReferenceFeeUnits", true),
    (0x021f, "ReserveBase", true),
    (0x0220, "ReserveIncrement", true),
    (0x0221, "SetFlag", true),
    (0x0222, "ClearFlag", true),
    (0x0223, "SignerQuorum", true),
    (0x0224, "CancelAfter", true),
    (0x0225, "FinishAfter", true),
    (0x0226, "SignerListID", true),
    (0x0227, "SettleDelay", true),
    (0x0228, "TicketCount", true),
    (0x0229, "TicketSequence", true),
    (0x022a, "NFTokenTaxon", true),
    (0x022b, "MintedNFTokens", true),
    (0x022c, "BurnedNFTokens", true),
    (0x0230, "VoteWeight", true),
    (0x0232, "FirstNFTokenSequence", true),
    (0x0233, "OracleDocumentID", true),
    (0x0234, "PermissionValue", true),
    (0x0235, "ImmutableFlags", true),
    (0x0236, "StartDate", true),
    (0x0237, "PaymentInterval", true),
    (0x0238, "GracePeriod", true),
    (0x0239, "PreviousPaymentDueDate", true),
    (0x023a, "NextPaymentDueDate", true),
    (0x023b, "PaymentRemaining", true),
    (0x023c, "PaymentTotal", true),
    (0x023d, "LoanSequence", true),
    (0x023e, "CoverRateMinimum", true),
    (0x023f, "CoverRateLiquidation", true),
    (0x0240, "OverpaymentFee", true),
    (0x0241, "InterestRate", true),
    (0x0242, "LateInterestRate", true),
    (0x0243, "CloseInterestRate", true),
    (0x0244, "OverpaymentInterestRate", true),
    (0x0245, "ConfidentialBalanceVersion", true),
    (0x0246, "SponsoredOwnerCount", true),
    (0x0247, "SponsoringOwnerCount", true),
    (0x0248, "SponsoringAccountCount", true),
    (0x0249, "RemainingOwnerCount", true),
    (0x024a, "SponsorFlags", true),
    (0x024b, "SubscriptionDate", true),
    (0x024c, "RedemptionDate", true),
    (0x024d, "IssuerKeyEpoch", true),
    (0x024e, "AuditorKeyEpoch", true),
    (0x024f, "IssuerKeyMirrorEpoch", true),
    (0x0250, "AuditorKeyMirrorEpoch", true),
    (0x0301, "IndexNext", true),
    (0x0302, "IndexPrevious", true),
    (0x0303, "BookNode", true),
    (0x0304, "OwnerNode", true),
    (0x0305, "BaseFee", true),
    (0x0306, "ExchangeRate", true),
    (0x0307, "LowNode", true),
    (0x0308, "HighNode", true),
    (0x0309, "DestinationNode", true),
    (0x030a, "Cookie", true),
    (0x030b, "ServerVersion", true),
    (0x030c, "NFTokenOfferNode", true),
    (0x030d, "EmitBurden", true),
    (0x0313, "ReferenceCount", true),
    (0x0314, "XChainClaimID", true),
    (0x0315, "XChainAccountCreateCount", true),
    (0x0316, "XChainAccountClaimCount", true),
    (0x0317, "AssetPrice", true),
    (0x0318, "MaximumAmount", true),
    (0x0319, "OutstandingAmount", true),
    (0x031a, "MPTAmount", true),
    (0x031b, "IssuerNode", true),
    (0x031c, "SubjectNode", true),
    (0x031d, "LockedAmount", true),
    (0x031e, "VaultNode", true),
    (0x031f, "LoanBrokerNode", true),
    (0x0320, "ConfidentialOutstandingAmount", true),
    (0x0321, "SponseeNode", true),
    (0x0401, "EmailHash", true),
    (0x0501, "LedgerHash", true),
    (0x0502, "ParentHash", true),
    (0x0503, "TransactionHash", true),
    (0x0504, "AccountHash", true),
    (0x0505, "PreviousTxnID", true),
    (0x0506, "LedgerIndex", true),
    (0x0507, "WalletLocator", true),
    (0x0508, "RootIndex", true),
    (0x0509, "AccountTxnID", true),
    (0x050a, "NFTokenID", true),
    (0x050b, "EmitParentTxnID", true),
    (0x050c, "EmitNonce", true),
    (0x050d, "EmitHookHash", true),
    (0x050e, "AMMID", true),
    (0x0510, "BookDirectory", true),
    (0x0511, "InvoiceID", true),
    (0x0512, "Nickname", true),
    (0x0513, "Amendment", true),
    (0x0515, "Digest", true),
    (0x0516, "Channel", true),
    (0x0517, "ConsensusHash", true),
    (0x0518, "CheckID", true),
    (0x0519, "ValidatedHash", true),
    (0x051a, "PreviousPageMin", true),
    (0x051b, "NextPageMin", true),
    (0x051c, "NFTokenBuyOffer", true),
    (0x051d, "NFTokenSellOffer", true),
    (0x0522, "DomainID", true),
    (0x0523, "VaultID", true),
    (0x0524, "ParentBatchID", true),
    (0x0525, "LoanBrokerID", true),
    (0x0526, "LoanID", true),
    (0x0527, "ReferenceHolding", true),
    (0x0528, "BlindingFactor", true),
    (0x0529, "ObjectID", true),
    (0x0601, "Amount", true),
    (0x0602, "Balance", true),
    (0x0603, "LimitAmount", true),
    (0x0604, "TakerPays", true),
    (0x0605, "TakerGets", true),
    (0x0606, "LowLimit", true),
    (0x0607, "HighLimit", true),
    (0x0608, "Fee", true),
    (0x0609, "SendMax", true),
    (0x060a, "DeliverMin", true),
    (0x060b, "Amount2", true),
    (0x060c, "BidMin", true),
    (0x060d, "BidMax", true),
    (0x0610, "MinimumOffer", true),
    (0x0611, "RippleEscrow", true),
    (0x0612, "DeliveredAmount", true),
    (0x0613, "NFTokenBrokerFee", true),
    (0x0616, "BaseFeeDrops", true),
    (0x0617, "ReserveBaseDrops", true),
    (0x0618, "ReserveIncrementDrops", true),
    (0x0619, "LPTokenOut", true),
    (0x061a, "LPTokenIn", true),
    (0x061b, "EPrice", true),
    (0x061c, "Price", true),
    (0x061d, "SignatureReward", true),
    (0x061e, "MinAccountCreateAmount", true),
    (0x061f, "LPTokenBalance", true),
    (0x0620, "FeeAmount", true),
    (0x0621, "MaxFee", true),
    (0x0622, "FeeAmountDelta", true),
    (0x0701, "PublicKey", true),
    (0x0702, "MessageKey", true),
    (0x0703, "SigningPubKey", true),
    (0x0704, "TxnSignature", false),
    (0x0705, "URI", true),
    (0x0706, "Signature", false),
    (0x0707, "Domain", true),
    (0x0708, "FundCode", true),
    (0x0709, "RemoveCode", true),
    (0x070a, "ExpireCode", true),
    (0x070b, "CreateCode", true),
    (0x070c, "MemoType", true),
    (0x070d, "MemoData", true),
    (0x070e, "MemoFormat", true),
    (0x0710, "Fulfillment", true),
    (0x0711, "Condition", true),
    (0x0712, "MasterSignature", false),
    (0x0713, "UNLModifyValidator", true),
    (0x0714, "ValidatorToDisable", true),
    (0x0715, "ValidatorToReEnable", true),
    (0x071a, "DIDDocument", true),
    (0x071b, "Data", true),
    (0x071c, "AssetClass", true),
    (0x071d, "Provider", true),
    (0x071e, "MPTokenMetadata", true),
    (0x071f, "CredentialType", true),
    (0x0720, "ConfidentialBalanceInbox", true),
    (0x0721, "ConfidentialBalanceSpending", true),
    (0x0722, "IssuerEncryptedBalance", true),
    (0x0723, "IssuerEncryptionKey", true),
    (0x0724, "HolderEncryptionKey", true),
    (0x0725, "ZKProof", true),
    (0x0726, "HolderEncryptedAmount", true),
    (0x0727, "IssuerEncryptedAmount", true),
    (0x0728, "SenderEncryptedAmount", true),
    (0x0729, "DestinationEncryptedAmount", true),
    (0x072a, "AuditorEncryptedBalance", true),
    (0x072b, "AuditorEncryptedAmount", true),
    (0x072c, "AuditorEncryptionKey", true),
    (0x072d, "AmountCommitment", true),
    (0x072e, "BalanceCommitment", true),
    (0x0801, "Account", true),
    (0x0802, "Owner", true),
    (0x0803, "Destination", true),
    (0x0804, "Issuer", true),
    (0x0805, "Authorize", true),
    (0x0806, "Unauthorize", true),
    (0x0808, "RegularKey", true),
    (0x0809, "NFTokenMinter", true),
    (0x080a, "EmitCallback", true),
    (0x080b, "Holder", true),
    (0x080c, "Delegate", true),
    (0x0812, "OtherChainSource", true),
    (0x0813, "OtherChainDestination", true),
    (0x0814, "AttestationSignerAccount", true),
    (0x0815, "AttestationRewardAccount", true),
    (0x0816, "LockingChainDoor", true),
    (0x0817, "IssuingChainDoor", true),
    (0x0818, "Subject", true),
    (0x0819, "Borrower", true),
    (0x081a, "Counterparty", true),
    (0x081b, "Sponsor", true),
    (0x081c, "HighSponsor", true),
    (0x081d, "LowSponsor", true),
    (0x081e, "CounterpartySponsor", true),
    (0x081f, "Sponsee", true),
    (0x0901, "Number", true),
    (0x0902, "AssetsAvailable", true),
    (0x0903, "AssetsMaximum", true),
    (0x0904, "AssetsTotal", true),
    (0x0905, "LossUnrealized", true),
    (0x0906, "DebtTotal", true),
    (0x0907, "DebtMaximum", true),
    (0x0908, "CoverAvailable", true),
    (0x0909, "LoanOriginationFee", true),
    (0x090a, "LoanServiceFee", true),
    (0x090b, "LatePaymentFee", true),
    (0x090c, "ClosePaymentFee", true),
    (0x090d, "PrincipalOutstanding", true),
    (0x090e, "PrincipalRequested", true),
    (0x090f, "TotalValueOutstanding", true),
    (0x0910, "PeriodicPayment", true),
    (0x0911, "ManagementFeeOutstanding", true),
    (0x0a01, "LoanScale", true),
    (0x0a02, "RemainingOwnerCountDelta", true),
    (0x0e01, "ObjectEndMarker", true),
    (0x0e02, "TransactionMetaData", true),
    (0x0e03, "CreatedNode", true),
    (0x0e04, "DeletedNode", true),
    (0x0e05, "ModifiedNode", true),
    (0x0e06, "PreviousFields", true),
    (0x0e07, "FinalFields", true),
    (0x0e08, "NewFields", true),
    (0x0e09, "TemplateEntry", true),
    (0x0e0a, "Memo", true),
    (0x0e0b, "SignerEntry", true),
    (0x0e0c, "NFToken", true),
    (0x0e0d, "EmitDetails", true),
    (0x0e0f, "Permission", true),
    (0x0e10, "Signer", true),
    (0x0e12, "Majority", true),
    (0x0e13, "DisabledValidator", true),
    (0x0e19, "VoteEntry", true),
    (0x0e1a, "AuctionSlot", true),
    (0x0e1b, "AuthAccount", true),
    (0x0e1c, "XChainClaimProofSig", true),
    (0x0e1d, "XChainCreateAccountProofSig", true),
    (0x0e1e, "XChainClaimAttestationCollectionElement", true),
    (0x0e1f, "XChainCreateAccountAttestationCollectionElement", true),
    (0x0e20, "PriceData", true),
    (0x0e21, "Credential", true),
    (0x0e22, "RawTransaction", true),
    (0x0e23, "BatchSigner", true),
    (0x0e24, "Book", true),
    (0x0e25, "CounterpartySignature", false),
    (0x0e26, "SponsorSignature", false),
    (0x0f01, "ArrayEndMarker", true),
    (0x0f03, "Signers", false),
    (0x0f04, "SignerEntries", true),
    (0x0f05, "Template", true),
    (0x0f06, "Necessary", true),
    (0x0f07, "Sufficient", true),
    (0x0f08, "AffectedNodes", true),
    (0x0f09, "Memos", true),
    (0x0f0a, "NFTokens", true),
    (0x0f0c, "VoteSlots", true),
    (0x0f0d, "AdditionalBooks", true),
    (0x0f10, "Majorities", true),
    (0x0f11, "DisabledValidators", true),
    (0x0f15, "XChainClaimAttestations", true),
    (0x0f16, "XChainCreateAccountAttestations", true),
    (0x0f18, "PriceDataSeries", true),
    (0x0f19, "AuthAccounts", true),
    (0x0f1a, "AuthorizeCredentials", true),
    (0x0f1b, "UnauthorizeCredentials", true),
    (0x0f1c, "AcceptedCredentials", true),
    (0x0f1d, "Permissions", true),
    (0x0f1e, "RawTransactions", true),
    (0x0f1f, "BatchSigners", false),
    (0x1001, "CloseResolution", true),
    (0x1002, "Method", true),
    (0x1003, "TransactionResult", true),
    (0x1004, "Scale", true),
    (0x1005, "AssetScale", true),
    (0x1006, "LEVersion", true),
    (0x1010, "TickSize", true),
    (0x1011, "UNLModifyDisabling", true),
    (0x1013, "WasLockingChainSend", true),
    (0x1014, "WithdrawalPolicy", true),
    (0x1015, "ContractResult", true),
    (0x1016, "VaultKind", true),
    (0x1101, "TakerPaysCurrency", true),
    (0x1102, "TakerPaysIssuer", true),
    (0x1103, "TakerGetsCurrency", true),
    (0x1104, "TakerGetsIssuer", true),
    (0x1201, "Paths", true),
    (0x1301, "Indexes", true),
    (0x1302, "Hashes", true),
    (0x1303, "Amendments", true),
    (0x1304, "NFTokenOffers", true),
    (0x1305, "CredentialIDs", true),
    (0x1501, "MPTokenIssuanceID", true),
    (0x1502, "ShareMPTID", true),
    (0x1503, "TakerPaysMPT", true),
    (0x1504, "TakerGetsMPT", true),
    (0x1801, "LockingChainIssue", true),
    (0x1802, "IssuingChainIssue", true),
    (0x1803, "Asset", true),
    (0x1804, "Asset2", true),
    (0x1901, "XChainBridge", true),
    (0x1a01, "BaseAsset", true),
    (0x1a02, "QuoteAsset", true),
];

/// The transaction types, by their code.
pub const TRANSACTION_TYPES: &[(u16, &str)] = &[
    (0, "Payment"),
    (1, "EscrowCreate"),
    (2, "EscrowFinish"),
    (3, "AccountSet"),
    (4, "EscrowCancel"),
    (5, "SetRegularKey"),
    (7, "OfferCreate"),
    (8, "OfferCancel"),
    (10, "TicketCreate"),
    (12, "SignerListSet"),
    (13, "PaymentChannelCreate"),
    (14, "PaymentChannelFund"),
    (15, "PaymentChannelClaim"),
    (16, "CheckCreate"),
    (17, "CheckCash"),
    (18, "CheckCancel"),
    (19, "DepositPreauth"),
    (20, "TrustSet"),
    (21, "AccountDelete"),
    (25, "NFTokenMint"),
    (26, "NFTokenBurn"),
    (27, "NFTokenCreateOffer"),
    (28, "NFTokenCancelOffer"),
    (29, "NFTokenAcceptOffer"),
    (30, "Clawback"),
    (31, "AMMClawback"),
    (35, "AMMCreate"),
    (36, "AMMDeposit"),
    (37, "AMMWithdraw"),
    (38, "AMMVote"),
    (39, "AMMBid"),
    (40, "AMMDelete"),
    (41, "XChainCreateClaimID"),
    (42, "XChainCommit"),
    (43, "XChainClaim"),
    (44, "XChainAccountCreateCommit"),
    (45, "XChainAddClaimAttestation"),
    (46, "XChainAddAccountCreateAttestation"),
    (47, "XChainModifyBridge"),
    (48, "XChainCreateBridge"),
    (49, "DIDSet"),
    (50, "DIDDelete"),
    (51, "OracleSet"),
    (52, "OracleDelete"),
    (53, "LedgerStateFix"),
    (54, "MPTokenIssuanceCreate"),
    (55, "MPTokenIssuanceDestroy"),
    (56, "MPTokenIssuanceSet"),
    (57, "MPTokenAuthorize"),
    (58, "CredentialCreate"),
    (59, "CredentialAccept"),
    (60, "CredentialDelete"),
    (61, "NFTokenModify"),
    (62, "PermissionedDomainSet"),
    (63, "PermissionedDomainDelete"),
    (64, "DelegateSet"),
    (65, "VaultCreate"),
    (66, "VaultSet"),
    (67, "VaultDelete"),
    (68, "VaultDeposit"),
    (69, "VaultWithdraw"),
    (70, "VaultClawback"),
    (71, "Batch"),
    (74, "LoanBrokerSet"),
    (75, "LoanBrokerDelete"),
    (76, "LoanBrokerCoverDeposit"),
    (77, "LoanBrokerCoverWithdraw"),
    (78, "LoanBrokerCoverClawback"),
    (80, "LoanSet"),
    (81, "LoanDelete"),
    (82, "LoanManage"),
    (84, "LoanPay"),
    (85, "ConfidentialMPTConvert"),
    (86, "ConfidentialMPTMergeInbox"),
    (87, "ConfidentialMPTConvertBack"),
    (88, "ConfidentialMPTSend"),
    (89, "ConfidentialMPTClawback"),
    (90, "SponsorshipTransfer"),
    (91, "SponsorshipSet"),
    (100, "EnableAmendment"),
    (101, "SetFee"),
    (102, "UNLModify"),
];

/// The fields every transaction may have, and whether it must.
pub const COMMON: &[(u16, u8)] = &[
    (0x0102, REQUIRED), // TransactionType
    (0x0202, OPTIONAL), // Flags
    (0x0203, OPTIONAL), // SourceTag
    (0x0801, REQUIRED), // Account
    (0x0204, REQUIRED), // Sequence
    (0x0505, OPTIONAL), // PreviousTxnID
    (0x021b, OPTIONAL), // LastLedgerSequence
    (0x0509, OPTIONAL), // AccountTxnID
    (0x0608, REQUIRED), // Fee
    (0x021d, OPTIONAL), // OperationLimit
    (0x0f09, OPTIONAL), // Memos
    (0x0703, REQUIRED), // SigningPubKey
    (0x0229, OPTIONAL), // TicketSequence
    (0x0704, OPTIONAL), // TxnSignature
    (0x0f03, OPTIONAL), // Signers
    (0x0201, OPTIONAL), // NetworkID
    (0x080c, OPTIONAL), // Delegate
    (0x081b, OPTIONAL), // Sponsor
    (0x024a, OPTIONAL), // SponsorFlags
    (0x0e26, OPTIONAL), // SponsorSignature
];

/// The fields each transaction type has besides the common ones: its code, the field, and
/// whether it must.
pub const FORMATS: &[(u16, u16, u8)] = &[
    (0, 0x0803, REQUIRED),   // Destination
    (0, 0x0601, REQUIRED),   // Amount
    (0, 0x0609, OPTIONAL),   // SendMax
    (0, 0x1201, DEFAULT),    // Paths
    (0, 0x0511, OPTIONAL),   // InvoiceID
    (0, 0x020e, OPTIONAL),   // DestinationTag
    (0, 0x060a, OPTIONAL),   // DeliverMin
    (0, 0x1305, OPTIONAL),   // CredentialIDs
    (0, 0x0522, OPTIONAL),   // DomainID
    (1, 0x0803, REQUIRED),   // Destination
    (1, 0x0601, REQUIRED),   // Amount
    (1, 0x0711, OPTIONAL),   // Condition
    (1, 0x0224, OPTIONAL),   // CancelAfter
    (1, 0x0225, OPTIONAL),   // FinishAfter
    (1, 0x020e, OPTIONAL),   // DestinationTag
    (2, 0x0802, REQUIRED),   // Owner
    (2, 0x0219, REQUIRED),   // OfferSequence
    (2, 0x0710, OPTIONAL),   // Fulfillment
    (2, 0x0711, OPTIONAL),   // Condition
    (2, 0x1305, OPTIONAL),   // CredentialIDs
    (3, 0x0401, OPTIONAL),   // EmailHash
    (3, 0x0507, OPTIONAL),   // WalletLocator
    (3, 0x020c, OPTIONAL),   // WalletSize
    (3, 0x0702, OPTIONAL),   // MessageKey
    (3, 0x0707, OPTIONAL),   // Domain
    (3, 0x020b, OPTIONAL),   // TransferRate
    (3, 0x0221, OPTIONAL),   // SetFlag
    (3, 0x0222, OPTIONAL),   // ClearFlag
    (3, 0x1010, OPTIONAL),   // TickSize
    (3, 0x0809, OPTIONAL),   // NFTokenMinter
    (4, 0x0802, REQUIRED),   // Owner
    (4, 0x0219, REQUIRED),   // OfferSequence
    (5, 0x0808, OPTIONAL),   // RegularKey
    (7, 0x0604, REQUIRED),   // TakerPays
    (7, 0x0605, REQUIRED),   // TakerGets
    (7, 0x020a, OPTIONAL),   // Expiration
    (7, 0x0219, OPTIONAL),   // OfferSequence
    (7, 0x0522, OPTIONAL),   // DomainID
    (8, 0x0219, REQUIRED),   // OfferSequence
    (10, 0x0228, REQUIRED),  // TicketCount
    (12, 0x0223, REQUIRED),  // SignerQuorum
    (12, 0x0f04, OPTIONAL),  // SignerEntries
    (13, 0x0803, REQUIRED),  // Destination
    (13, 0x0601, REQUIRED),  // Amount
    (13, 0x0227, REQUIRED),  // SettleDelay
    (13, 0x0701, REQUIRED),  // PublicKey
    (13, 0x0224, OPTIONAL),  // CancelAfter
    (13, 0x020e, OPTIONAL),  // DestinationTag
    (14, 0x0516, REQUIRED),  // Channel
    (14, 0x0601, REQUIRED),  // Amount
    (14, 0x020a, OPTIONAL),  // Expiration
    (15, 0x0516, REQUIRED),  // Channel
    (15, 0x0601, OPTIONAL),  // Amount
    (15, 0x0602, OPTIONAL),  // Balance
    (15, 0x0706, OPTIONAL),  // Signature
    (15, 0x0701, OPTIONAL),  // PublicKey
    (15, 0x1305, OPTIONAL),  // CredentialIDs
    (16, 0x0803, REQUIRED),  // Destination
    (16, 0x0609, REQUIRED),  // SendMax
    (16, 0x020a, OPTIONAL),  // Expiration
    (16, 0x020e, OPTIONAL),  // DestinationTag
    (16, 0x0511, OPTIONAL),  // InvoiceID
    (17, 0x0518, REQUIRED),  // CheckID
    (17, 0x0601, OPTIONAL),  // Amount
    (17, 0x060a, OPTIONAL),  // DeliverMin
    (18, 0x0518, REQUIRED),  // CheckID
    (19, 0x0805, OPTIONAL),  // Authorize
    (19, 0x0806, OPTIONAL),  // Unauthorize
    (19, 0x0f1a, OPTIONAL),  // AuthorizeCredentials
    (19, 0x0f1b, OPTIONAL),  // UnauthorizeCredentials
    (20, 0x0603, OPTIONAL),  // LimitAmount
    (20, 0x0214, OPTIONAL),  // QualityIn
    (20, 0x0215, OPTIONAL),  // QualityOut
    (21, 0x0803, REQUIRED),  // Destination
    (21, 0x020e, OPTIONAL),  // DestinationTag
    (21, 0x1305, OPTIONAL),  // CredentialIDs
    (25, 0x022a, REQUIRED),  // NFTokenTaxon
    (25, 0x0104, OPTIONAL),  // TransferFee
    (25, 0x0804, OPTIONAL),  // Issuer
    (25, 0x0705, OPTIONAL),  // URI
    (25, 0x0601, OPTIONAL),  // Amount
    (25, 0x0803, OPTIONAL),  // Destination
    (25, 0x020a, OPTIONAL),  // Expiration
    (26, 0x050a, REQUIRED),  // NFTokenID
    (26, 0x0802, OPTIONAL),  // Owner
    (27, 0x050a, REQUIRED),  // NFTokenID
    (27, 0x0601, REQUIRED),  // Amount
    (27, 0x0803, OPTIONAL),  // Destination
    (27, 0x0802, OPTIONAL),  // Owner
    (27, 0x020a, OPTIONAL),  // Expiration
    (28, 0x1304, REQUIRED),  // NFTokenOffers
    (29, 0x051c, OPTIONAL),  // NFTokenBuyOffer
    (29, 0x051d, OPTIONAL),  // NFTokenSellOffer
    (29, 0x0613, OPTIONAL),  // NFTokenBrokerFee
    (30, 0x0601, REQUIRED),  // Amount
    (30, 0x080b, OPTIONAL),  // Holder
    (31, 0x080b, REQUIRED),  // Holder
    (31, 0x1803, REQUIRED),  // Asset
    (31, 0x1804, REQUIRED),  // Asset2
    (31, 0x0601, OPTIONAL),  // Amount
    (35, 0x0601, REQUIRED),  // Amount
    (35, 0x060b, REQUIRED),  // Amount2
    (35, 0x0105, REQUIRED),  // TradingFee
    (36, 0x1803, REQUIRED),  // Asset
    (36, 0x1804, REQUIRED),  // Asset2
    (36, 0x0601, OPTIONAL),  // Amount
    (36, 0x060b, OPTIONAL),  // Amount2
    (36, 0x061b, OPTIONAL),  // EPrice
    (36, 0x0619, OPTIONAL),  // LPTokenOut
    (36, 0x0105, OPTIONAL),  // TradingFee
    (37, 0x1803, REQUIRED),  // Asset
    (37, 0x1804, REQUIRED),  // Asset2
    (37, 0x0601, OPTIONAL),  // Amount
    (37, 0x060b, OPTIONAL),  // Amount2
    (37, 0x061b, OPTIONAL),  // EPrice
    (37, 0x061a, OPTIONAL),  // LPTokenIn
    (38, 0x1803, REQUIRED),  // Asset
    (38, 0x1804, REQUIRED),  // Asset2
    (38, 0x0105, REQUIRED),  // TradingFee
    (39, 0x1803, REQUIRED),  // Asset
    (39, 0x1804, REQUIRED),  // Asset2
    (39, 0x060c, OPTIONAL),  // BidMin
    (39, 0x060d, OPTIONAL),  // BidMax
    (39, 0x0f19, OPTIONAL),  // AuthAccounts
    (40, 0x1803, REQUIRED),  // Asset
    (40, 0x1804, REQUIRED),  // Asset2
    (41, 0x1901, REQUIRED),  // XChainBridge
    (41, 0x061d, REQUIRED),  // SignatureReward
    (41, 0x0812, REQUIRED),  // OtherChainSource
    (42, 0x1901, REQUIRED),  // XChainBridge
    (42, 0x0314, REQUIRED),  // XChainClaimID
    (42, 0x0601, REQUIRED),  // Amount
    (42, 0x0813, OPTIONAL),  // OtherChainDestination
    (43, 0x1901, REQUIRED),  // XChainBridge
    (43, 0x0314, REQUIRED),  // XChainClaimID
    (43, 0x0803, REQUIRED),  // Destination
    (43, 0x020e, OPTIONAL),  // DestinationTag
    (43, 0x0601, REQUIRED),  // Amount
    (44, 0x1901, REQUIRED),  // XChainBridge
    (44, 0x0803, REQUIRED),  // Destination
    (44, 0x0601, REQUIRED),  // Amount
    (44, 0x061d, REQUIRED),  // SignatureReward
    (45, 0x1901, REQUIRED),  // XChainBridge
    (45, 0x0814, REQUIRED),  // AttestationSignerAccount
    (45, 0x0701, REQUIRED),  // PublicKey
    (45, 0x0706, REQUIRED),  // Signature
    (45, 0x0812, REQUIRED),  // OtherChainSource
    (45, 0x0601, REQUIRED),  // Amount
    (45, 0x0815, REQUIRED),  // AttestationRewardAccount
    (45, 0x1013, REQUIRED),  // WasLockingChainSend
    (45, 0x0314, REQUIRED),  // XChainClaimID
    (45, 0x0803, OPTIONAL),  // Destination
    (46, 0x1901, REQUIRED),  // XChainBridge
    (46, 0x0814, REQUIRED),  // AttestationSignerAccount
    (46, 0x0701, REQUIRED),  // PublicKey
    (46, 0x0706, REQUIRED),  // Signature
    (46, 0x0812, REQUIRED),  // OtherChainSource
    (46, 0x0601, REQUIRED),  // Amount
    (46, 0x0815, REQUIRED),  // AttestationRewardAccount
    (46, 0x1013, REQUIRED),  // WasLockingChainSend
    (46, 0x0315, REQUIRED),  // XChainAccountCreateCount
    (46, 0x0803, REQUIRED),  // Destination
    (46, 0x061d, REQUIRED),  // SignatureReward
    (47, 0x1901, REQUIRED),  // XChainBridge
    (47, 0x061d, OPTIONAL),  // SignatureReward
    (47, 0x061e, OPTIONAL),  // MinAccountCreateAmount
    (48, 0x1901, REQUIRED),  // XChainBridge
    (48, 0x061d, REQUIRED),  // SignatureReward
    (48, 0x061e, OPTIONAL),  // MinAccountCreateAmount
    (49, 0x071a, OPTIONAL),  // DIDDocument
    (49, 0x0705, OPTIONAL),  // URI
    (49, 0x071b, OPTIONAL),  // Data
    (51, 0x0233, REQUIRED),  // OracleDocumentID
    (51, 0x071d, OPTIONAL),  // Provider
    (51, 0x0705, OPTIONAL),  // URI
    (51, 0x071c, OPTIONAL),  // AssetClass
    (51, 0x020f, REQUIRED),  // LastUpdateTime
    (51, 0x0f18, REQUIRED),  // PriceDataSeries
    (52, 0x0233, REQUIRED),  // OracleDocumentID
    (53, 0x0115, REQUIRED),  // LedgerFixType
    (53, 0x0802, OPTIONAL),  // Owner
    (53, 0x0510, OPTIONAL),  // BookDirectory
    (54, 0x1005, OPTIONAL),  // AssetScale
    (54, 0x0104, OPTIONAL),  // TransferFee
    (54, 0x0318, OPTIONAL),  // MaximumAmount
    (54, 0x071e, OPTIONAL),  // MPTokenMetadata
    (54, 0x0522, OPTIONAL),  // DomainID
    (54, 0x0235, OPTIONAL),  // ImmutableFlags
    (55, 0x1501, REQUIRED),  // MPTokenIssuanceID
    (56, 0x1501, REQUIRED),  // MPTokenIssuanceID
    (56, 0x080b, OPTIONAL),  // Holder
    (56, 0x0522, OPTIONAL),  // DomainID
    (56, 0x071e, OPTIONAL),  // MPTokenMetadata
    (56, 0x0104, OPTIONAL),  // TransferFee
    (56, 0x0235, OPTIONAL),  // ImmutableFlags
    (56, 0x0723, OPTIONAL),  // IssuerEncryptionKey
    (56, 0x072c, OPTIONAL),  // AuditorEncryptionKey
    (57, 0x1501, REQUIRED),  // MPTokenIssuanceID
    (57, 0x080b, OPTIONAL),  // Holder
    (58, 0x0818, REQUIRED),  // Subject
    (58, 0x071f, REQUIRED),  // CredentialType
    (58, 0x020a, OPTIONAL),  // Expiration
    (58, 0x0705, OPTIONAL),  // URI
    (59, 0x0804, REQUIRED),  // Issuer
    (59, 0x071f, REQUIRED),  // CredentialType
    (60, 0x0818, OPTIONAL),  // Subject
    (60, 0x0804, OPTIONAL),  // Issuer
    (60, 0x071f, REQUIRED),  // CredentialType
    (61, 0x050a, REQUIRED),  // NFTokenID
    (61, 0x0802, OPTIONAL),  // Owner
    (61, 0x0705, OPTIONAL),  // URI
    (62, 0x0522, OPTIONAL),  // DomainID
    (62, 0x0f1c, REQUIRED),  // AcceptedCredentials
    (63, 0x0522, REQUIRED),  // DomainID
    (64, 0x0805, REQUIRED),  // Authorize
    (64, 0x0f1d, REQUIRED),  // Permissions
    (65, 0x1803, REQUIRED),  // Asset
    (65, 0x0903, OPTIONAL),  // AssetsMaximum
    (65, 0x071e, OPTIONAL),  // MPTokenMetadata
    (65, 0x0522, OPTIONAL),  // DomainID
    (65, 0x1014, OPTIONAL),  // WithdrawalPolicy
    (65, 0x071b, OPTIONAL),  // Data
    (65, 0x1004, OPTIONAL),  // Scale
    (65, 0x1016, OPTIONAL),  // VaultKind
    (65, 0x024b, OPTIONAL),  // SubscriptionDate
    (65, 0x024c, OPTIONAL),  // RedemptionDate
    (66, 0x0523, REQUIRED),  // VaultID
    (66, 0x0903, OPTIONAL),  // AssetsMaximum
    (66, 0x0522, OPTIONAL),  // DomainID
    (66, 0x071b, OPTIONAL),  // Data
    (67, 0x0523, REQUIRED),  // VaultID
    (67, 0x070d, OPTIONAL),  // MemoData
    (68, 0x0523, REQUIRED),  // VaultID
    (68, 0x0601, REQUIRED),  // Amount
    (69, 0x0523, REQUIRED),  // VaultID
    (69, 0x0601, REQUIRED),  // Amount
    (69, 0x0803, OPTIONAL),  // Destination
    (69, 0x020e, OPTIONAL),  // DestinationTag
    (69, 0x1305, OPTIONAL),  // CredentialIDs
    (70, 0x0523, REQUIRED),  // VaultID
    (70, 0x080b, REQUIRED),  // Holder
    (70, 0x0601, OPTIONAL),  // Amount
    (71, 0x0f1e, REQUIRED),  // RawTransactions
    (71, 0x0f1f, OPTIONAL),  // BatchSigners
    (74, 0x0523, REQUIRED),  // VaultID
    (74, 0x0525, OPTIONAL),  // LoanBrokerID
    (74, 0x071b, OPTIONAL),  // Data
    (74, 0x0116, OPTIONAL),  // ManagementFeeRate
    (74, 0x0907, OPTIONAL),  // DebtMaximum
    (74, 0x023e, OPTIONAL),  // CoverRateMinimum
    (74, 0x023f, OPTIONAL),  // CoverRateLiquidation
    (75, 0x0525, REQUIRED),  // LoanBrokerID
    (76, 0x0525, REQUIRED),  // LoanBrokerID
    (76, 0x0601, REQUIRED),  // Amount
    (77, 0x0525, REQUIRED),  // LoanBrokerID
    (77, 0x0601, REQUIRED),  // Amount
    (77, 0x0803, OPTIONAL),  // Destination
    (77, 0x020e, OPTIONAL),  // DestinationTag
    (77, 0x1305, OPTIONAL),  // CredentialIDs
    (78, 0x0525, OPTIONAL),  // LoanBrokerID
    (78, 0x0601, OPTIONAL),  // Amount
    (80, 0x0525, REQUIRED),  // LoanBrokerID
    (80, 0x071b, OPTIONAL),  // Data
    (80, 0x081a, OPTIONAL),  // Counterparty
    (80, 0x0e25, OPTIONAL),  // CounterpartySignature
    (80, 0x0909, OPTIONAL),  // LoanOriginationFee
    (80, 0x090a, OPTIONAL),  // LoanServiceFee
    (80, 0x090b, OPTIONAL),  // LatePaymentFee
    (80, 0x090c, OPTIONAL),  // ClosePaymentFee
    (80, 0x0240, OPTIONAL),  // OverpaymentFee
    (80, 0x0241, OPTIONAL),  // InterestRate
    (80, 0x0242, OPTIONAL),  // LateInterestRate
    (80, 0x0243, OPTIONAL),  // CloseInterestRate
    (80, 0x0244, OPTIONAL),  // OverpaymentInterestRate
    (80, 0x090e, REQUIRED),  // PrincipalRequested
    (80, 0x023c, OPTIONAL),  // PaymentTotal
    (80, 0x0237, OPTIONAL),  // PaymentInterval
    (80, 0x0238, OPTIONAL),  // GracePeriod
    (81, 0x0526, REQUIRED),  // LoanID
    (82, 0x0526, REQUIRED),  // LoanID
    (84, 0x0526, REQUIRED),  // LoanID
    (84, 0x0601, REQUIRED),  // Amount
    (85, 0x1501, REQUIRED),  // MPTokenIssuanceID
    (85, 0x031a, REQUIRED),  // MPTAmount
    (85, 0x0724, OPTIONAL),  // HolderEncryptionKey
    (85, 0x0726, REQUIRED),  // HolderEncryptedAmount
    (85, 0x0727, REQUIRED),  // IssuerEncryptedAmount
    (85, 0x072b, OPTIONAL),  // AuditorEncryptedAmount
    (85, 0x0528, REQUIRED),  // BlindingFactor
    (85, 0x0725, OPTIONAL),  // ZKProof
    (86, 0x1501, REQUIRED),  // MPTokenIssuanceID
    (87, 0x1501, REQUIRED),  // MPTokenIssuanceID
    (87, 0x031a, REQUIRED),  // MPTAmount
    (87, 0x0726, REQUIRED),  // HolderEncryptedAmount
    (87, 0x0727, REQUIRED),  // IssuerEncryptedAmount
    (87, 0x072b, OPTIONAL),  // AuditorEncryptedAmount
    (87, 0x0528, REQUIRED),  // BlindingFactor
    (87, 0x0725, REQUIRED),  // ZKProof
    (87, 0x072e, REQUIRED),  // BalanceCommitment
    (88, 0x1501, REQUIRED),  // MPTokenIssuanceID
    (88, 0x0803, REQUIRED),  // Destination
    (88, 0x020e, OPTIONAL),  // DestinationTag
    (88, 0x0728, REQUIRED),  // SenderEncryptedAmount
    (88, 0x0729, REQUIRED),  // DestinationEncryptedAmount
    (88, 0x0727, REQUIRED),  // IssuerEncryptedAmount
    (88, 0x072b, OPTIONAL),  // AuditorEncryptedAmount
    (88, 0x0725, REQUIRED),  // ZKProof
    (88, 0x072d, REQUIRED),  // AmountCommitment
    (88, 0x072e, REQUIRED),  // BalanceCommitment
    (88, 0x1305, OPTIONAL),  // CredentialIDs
    (89, 0x1501, REQUIRED),  // MPTokenIssuanceID
    (89, 0x080b, REQUIRED),  // Holder
    (89, 0x031a, REQUIRED),  // MPTAmount
    (89, 0x0725, REQUIRED),  // ZKProof
    (90, 0x0529, OPTIONAL),  // ObjectID
    (90, 0x081f, OPTIONAL),  // Sponsee
    (91, 0x081e, OPTIONAL),  // CounterpartySponsor
    (91, 0x081f, OPTIONAL),  // Sponsee
    (91, 0x0622, OPTIONAL),  // FeeAmountDelta
    (91, 0x0621, OPTIONAL),  // MaxFee
    (91, 0x0a02, OPTIONAL),  // RemainingOwnerCountDelta
    (100, 0x0206, REQUIRED), // LedgerSequence
    (100, 0x0513, REQUIRED), // Amendment
    (101, 0x0206, OPTIONAL), // LedgerSequence
    (101, 0x0305, OPTIONAL), // BaseFee
    (101, 0x021e, OPTIONAL), // ReferenceFeeUnits
    (101, 0x021f, OPTIONAL), // ReserveBase
    (101, 0x0220, OPTIONAL), // ReserveIncrement
    (101, 0x0616, OPTIONAL), // BaseFeeDrops
    (101, 0x0617, OPTIONAL), // ReserveBaseDrops
    (101, 0x0618, OPTIONAL), // ReserveIncrementDrops
    (102, 0x1011, REQUIRED), // UNLModifyDisabling
    (102, 0x0206, REQUIRED), // LedgerSequence
    (102, 0x0713, REQUIRED), // UNLModifyValidator
];
