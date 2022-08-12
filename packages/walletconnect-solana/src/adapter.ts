import WalletConnectClient from '@walletconnect/sign-client';
import QRCodeModal from '@walletconnect/qrcode-modal';
import { PublicKey } from '@solana/web3.js';

import { ClientNotInitializedError, QRCodeModalError } from './errors';

import type { EngineTypes, SessionTypes, SignClientTypes } from '@walletconnect/types';
import type { Transaction } from '@solana/web3.js';
import { getSdkError, parseAccountId } from '@walletconnect/utils';
import base58 from 'bs58';

export interface WalletConnectWalletAdapterConfig {
    network: WalletConnectChainID;
    options: SignClientTypes.Options;
}

export enum WalletConnectChainID {
    Mainnet = 'solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ',
    Devnet = 'solana:8E9rvCKLFQia2Y35HXjjpWzj8weVo44K',
}

export enum WalletConnectRPCMethods {
    signTransaction = 'solana_signTransaction',
    signMessage = 'solana_signMessage',
}

interface WalletConnectWalletInit {
    publicKey: PublicKey;
}

const getConnectParams = (chainId: WalletConnectChainID, pairingTopic?: string): EngineTypes.ConnectParams => ({
    requiredNamespaces: {
        solana: {
            chains: [chainId],
            methods: [WalletConnectRPCMethods.signTransaction, WalletConnectRPCMethods.signMessage],
            events: [],
        },
    },
    pairingTopic,
});

export class WalletConnectWallet {
    private _client: WalletConnectClient | undefined;
    private _session: SessionTypes.Struct | undefined;
    private _network: WalletConnectChainID;
    private _options: SignClientTypes.Options;

    constructor(config: WalletConnectWalletAdapterConfig) {
        this._options = config.options;
        this._network = config.network;
    }

    async connect(): Promise<WalletConnectWalletInit> {
        const client = await WalletConnectClient.init(this._options);

        const pairings = client.pairing.getAll({ active: true });
        // Prototypically, the user should be prompted to either:
        // - Connect to a previously active pairing
        // - Choose a new pairing
        // There doesn't seem to be a WalletConnect-provided UI for this like there exists for the QRCode modal, though,
        // and pushing this into user-land would be way too much
        // If we decide to try and pair automatically, the UI will hang waiting for a pairing that might not complete
        // const lastActivePairing = pairings.length ? pairings[pairings.length - 1].topic : undefined;
        const lastActivePairing = undefined;

        const { uri, approval } = await client.connect(getConnectParams(this._network, lastActivePairing));

        if (uri) {
            QRCodeModal.open(uri, () => {
                throw new QRCodeModalError();
            });
        }

        this._session = await approval();
        // We assign this variable only after we're sure we've received approval
        this._client = client;

        QRCodeModal.close();

        return {
            publicKey: this.publicKey,
        };
    }

    async disconnect() {
        if (this._client && this._session) {
            return await this._client.disconnect({
                topic: this._session.topic,
                reason: getSdkError('USER_DISCONNECTED'),
            });
        } else {
            throw new ClientNotInitializedError();
        }
    }

    get client(): WalletConnectClient {
        if (this._client) {
            return this._client;
        } else {
            throw new ClientNotInitializedError();
        }
    }

    get publicKey(): PublicKey {
        if (this._client && this._session) {
            const { address } = parseAccountId(this._session.namespaces.solana.accounts[0]);
            return new PublicKey(address);
        } else {
            throw new ClientNotInitializedError();
        }
    }

    async signTransaction(transaction: Transaction): Promise<Transaction> {
        if (this._client && this._session) {
            const { signature } = await this._client.request<{ signature: string }>({
                chainId: this._network,
                topic: this._session.topic,
                request: { method: WalletConnectRPCMethods.signTransaction, params: { ...transaction } },
            });
            transaction.addSignature(this.publicKey, Buffer.from(base58.decode(signature)));

            return transaction;
        } else {
            throw new ClientNotInitializedError();
        }
    }

    async signMessage(message: Uint8Array): Promise<Uint8Array> {
        if (this._client && this._session) {
            const { signature } = await this._client.request({
                // The network does not change the output of message signing, but this is a required parameter for SignClient
                chainId: this._network,
                topic: this._session.topic,
                request: {
                    method: WalletConnectRPCMethods.signMessage,
                    params: { pubkey: this.publicKey.toString(), message: base58.encode(message) },
                },
            });

            return base58.decode(signature);
        } else {
            throw new ClientNotInitializedError();
        }
    }
}
