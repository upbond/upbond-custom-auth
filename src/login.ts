import { TORUS_NETWORK } from "@toruslabs/constants";
import { NodeDetailManager } from "@toruslabs/fetch-node-details";
import Torus, { keccak256 } from "@toruslabs/torus.js";
import { UserManager } from "oidc-client";

import createHandler from "./handlers/HandlerFactory";
import {
  CustomAuthArgs,
  ExtraParams,
  ILoginHandler,
  InitParams,
  LoginWindowResponse,
  RedirectResult,
  SingleLoginParams,
  SubVerifierDetails,
  TorusKey,
  TorusSubVerifierInfo,
} from "./handlers/interfaces";
import { registerServiceWorker } from "./registerServiceWorker";
import SentryHandler from "./sentry";
import { LOGIN, SENTRY_TXNS, TORUS_METHOD, UX_MODE, UX_MODE_TYPE } from "./utils/enums";
import { handleRedirectParameters, isFirefox, padUrlString } from "./utils/helpers";
import log from "./utils/loglevel";
import StorageHelper from "./utils/StorageHelper";

class CustomAuth {
  isInitialized: boolean;

  config: {
    baseUrl: string;
    redirectToOpener: boolean;
    redirect_uri: string;
    uxMode: UX_MODE_TYPE;
    locationReplaceOnRedirect: boolean;
    popupFeatures: string;
  };

  torus: Torus;

  nodeDetailManager: NodeDetailManager;

  storageHelper: StorageHelper;

  sentryHandler: SentryHandler;

  userManager: UserManager;

  constructor({
    baseUrl,
    network = TORUS_NETWORK.MAINNET,
    enableLogging = false,
    enableOneKey = false,
    redirectToOpener = false,
    redirectPathName = "redirect",
    apiKey = "torus-default",
    uxMode = UX_MODE.POPUP,
    locationReplaceOnRedirect = false,
    popupFeatures,
    metadataUrl = "https://metadata.tor.us",
    storageServerUrl = "https://broadcast-server.tor.us",
    sentry,
    web3AuthClientId,
  }: CustomAuthArgs) {
    if (!web3AuthClientId) throw Error("Please provide a valid web3AuthClientId in constructor");
    this.isInitialized = false;
    const baseUri = new URL(baseUrl);
    this.config = {
      baseUrl: padUrlString(baseUri),
      get redirect_uri() {
        return `${this.baseUrl}${redirectPathName}`;
      },
      redirectToOpener,
      uxMode,
      locationReplaceOnRedirect,
      popupFeatures,
    };
    const torus = new Torus({
      enableOneKey,
      metadataHost: metadataUrl,
      network,
      clientId: web3AuthClientId,
    });
    Torus.setAPIKey(apiKey);
    this.torus = torus;
    this.nodeDetailManager = new NodeDetailManager({ network });
    if (enableLogging) log.enableAll();
    else log.disableAll();
    this.storageHelper = new StorageHelper(storageServerUrl);
    this.sentryHandler = new SentryHandler(sentry);
  }

  async initOIDC(auth, client, redirect_uri): Promise<void> {
    const oidcConfig = {
      authority: auth,
      client_id: client,
      response_type: "token id_token",
      scope: "openid profile email offline_access",
      redirect_uri,
      extraQueryParams: { prompt: "login" },
    };
    this.userManager = new UserManager(oidcConfig);
  }

  async init({ skipSw = false, skipInit = false, skipPrefetch = false }: InitParams = {}): Promise<void> {
    this.storageHelper.init();
    if (skipInit) {
      this.isInitialized = true;
      return;
    }
    if (!skipSw) {
      const fetchSwResponse = await fetch(`${this.config.baseUrl}sw.js`, { cache: "reload" });
      if (fetchSwResponse.ok) {
        try {
          await registerServiceWorker(this.config.baseUrl);
          this.isInitialized = true;
          return;
        } catch (error) {
          log.warn(error);
        }
      } else {
        throw new Error("Service worker is not being served. Please serve it");
      }
    }
    if (!skipPrefetch) {
      // Skip the redirect check for firefox
      if (isFirefox()) {
        this.isInitialized = true;
        return;
      }
      await this.handlePrefetchRedirectUri();
      return;
    }
    this.isInitialized = true;
  }

  async triggerLogin(args: SingleLoginParams) {
    const { verifier, typeOfLogin, clientId, jwtParams, hash, queryParameters, customState, registerOnly } = args;
    log.info("Verifier: ", verifier);
    if (!this.isInitialized) {
      throw new Error("Not initialized yet");
    }
    if (registerOnly && typeOfLogin !== LOGIN.WEBAUTHN) throw new Error("registerOnly flag can only be passed for webauthn");
    const loginHandler: ILoginHandler = createHandler({
      typeOfLogin,
      clientId,
      verifier,
      redirect_uri: this.config.redirect_uri,
      redirectToOpener: this.config.redirectToOpener,
      jwtParams,
      uxMode: this.config.uxMode,
      customState,
      registerOnly,
    });
    let loginParams: LoginWindowResponse;
    if (hash && queryParameters) {
      const { error, hashParameters, instanceParameters } = handleRedirectParameters(hash, queryParameters);
      if (error) throw new Error(error);
      const { access_token: accessToken, id_token: idToken, ...rest } = hashParameters;
      // State has to be last here otherwise it will be overwritten
      loginParams = { accessToken, idToken, ...rest, state: instanceParameters };
    } else {
      this.storageHelper.clearOrphanedLoginDetails();
      if (this.config.uxMode === UX_MODE.REDIRECT) {
        await this.storageHelper.storeLoginDetails({ method: TORUS_METHOD.TRIGGER_LOGIN, args }, loginHandler.nonce);
      }
      this.initOIDC(jwtParams.domain, clientId, this.config.redirect_uri);
      this.userManager.signinRedirect();
      if (this.config.uxMode === UX_MODE.REDIRECT) return null;
    }

    const userInfo = await loginHandler.getUserInfo(loginParams);
    return {
      userInfo: {
        ...userInfo,
        ...loginParams,
      },
    };
  }

  async SyncToTorusBlockchain(args) {
    const { verifier, accessToken, idToken, verifierId } = args;
    const torusKey = await this.getTorusKey(verifier, verifierId, { verifier_id: verifierId }, idToken || accessToken);
    return {
      result: {
        ...torusKey,
      },
    };
  }

  async getTorusKey(
    verifier: string,
    verifierId: string,
    verifierParams: { verifier_id: string },
    idToken: string,
    additionalParams?: ExtraParams
  ): Promise<TorusKey> {
    const nodeTx = this.sentryHandler.startTransaction({
      name: SENTRY_TXNS.FETCH_NODE_DETAILS,
    });
    const { torusNodeEndpoints, torusNodePub, torusIndexes } = await this.nodeDetailManager.getNodeDetails({ verifier, verifierId });
    this.sentryHandler.finishTransaction(nodeTx);
    log.debug("torus-direct/getTorusKey", { torusNodeEndpoints, torusNodePub, torusIndexes });

    const pubLookupTx = this.sentryHandler.startTransaction({
      name: SENTRY_TXNS.PUB_ADDRESS_LOOKUP,
    });
    const address = await this.torus.getPublicAddress(torusNodeEndpoints, torusNodePub, { verifier, verifierId }, true);
    this.sentryHandler.finishTransaction(pubLookupTx);
    if (typeof address === "string") throw new Error("must use extended pub key");
    log.debug("torus-direct/getTorusKey", { getPublicAddress: address });

    const sharesTx = this.sentryHandler.startTransaction({
      name: SENTRY_TXNS.FETCH_SHARES,
    });
    const shares = await this.torus.retrieveShares(torusNodeEndpoints, torusIndexes, verifier, verifierParams, idToken, additionalParams);
    this.sentryHandler.finishTransaction(sharesTx);
    if (shares.ethAddress.toLowerCase() !== address.address.toLowerCase()) {
      throw new Error("data ethAddress does not match response address");
    }
    log.debug("torus-direct/getTorusKey", { retrieveShares: shares });

    return {
      publicAddress: shares.ethAddress.toString(),
      privateKey: shares.privKey.toString(),
      metadataNonce: shares.metadataNonce.toString("hex"),
      typeOfUser: address.typeOfUser,
      pubKey: {
        pub_key_X: address.X,
        pub_key_Y: address.Y,
      },
    };
  }

  async getAggregateTorusKey(
    verifier: string,
    verifierId: string, // unique identifier for user e.g. sub on jwt
    subVerifierInfoArray: TorusSubVerifierInfo[]
  ): Promise<TorusKey> {
    const aggregateVerifierParams = { verify_params: [], sub_verifier_ids: [], verifier_id: "" };
    const aggregateIdTokenSeeds = [];
    let extraVerifierParams = {};
    for (let index = 0; index < subVerifierInfoArray.length; index += 1) {
      const userInfo = subVerifierInfoArray[index];
      aggregateVerifierParams.verify_params.push({ verifier_id: verifierId, idtoken: userInfo.idToken });
      aggregateVerifierParams.sub_verifier_ids.push(userInfo.verifier);
      aggregateIdTokenSeeds.push(userInfo.idToken);
      extraVerifierParams = userInfo.extraVerifierParams;
    }
    aggregateIdTokenSeeds.sort();
    const aggregateIdToken = keccak256(Buffer.from(aggregateIdTokenSeeds.join(String.fromCharCode(29)), "utf8")).slice(2);
    aggregateVerifierParams.verifier_id = verifierId;
    return this.getTorusKey(verifier, verifierId, aggregateVerifierParams, aggregateIdToken, extraVerifierParams);
  }

  getPostboxKeyFrom1OutOf1(privKey: string, nonce: string): string {
    return this.torus.getPostboxKeyFrom1OutOf1(privKey, nonce);
  }

  async getUserinfoAndStates(replaceUrl, hashParams): Promise<RedirectResult> {
    await this.init({ skipInit: true });
    const queryParams = {};
    const params = new URLSearchParams(hashParams);
    params.forEach((value, key) => {
      queryParams[key] = value;
    });

    if (replaceUrl) {
      const cleanUrl = window.location.origin + window.location.pathname;
      window.history.replaceState(null, "", cleanUrl);
    }

    const { error, instanceParameters, hashParameters } = handleRedirectParameters(hashParams, queryParams);

    const { instanceId } = instanceParameters;

    log.info(instanceId, "instanceId");

    const { args, method, ...rest } = await this.storageHelper.retrieveLoginDetails(instanceId);
    log.info(args, method);

    this.storageHelper.clearLoginDetailsStorage(instanceId);

    if (error) {
      return { error, state: instanceParameters || {}, method, result: {}, hashParameters, args };
    }

    let result: unknown;

    try {
      if (method === TORUS_METHOD.TRIGGER_LOGIN) {
        const methodArgs = args as SubVerifierDetails & { registerOnly?: boolean };
        methodArgs.hash = hashParams;
        methodArgs.queryParameters = queryParams;
        result = await this.triggerLogin(methodArgs);
      }
    } catch (err) {
      log.error(err);
      return {
        error: `Could not get result from torus nodes \n ${err?.message || ""}`,
        state: instanceParameters || {},
        method,
        result: {},
        hashParameters,
        args,
        ...rest,
      };
    }

    if (!result)
      return {
        error: "Unsupported method type",
        state: instanceParameters || {},
        method,
        result: {},
        hashParameters,
        args,
        ...rest,
      };

    return { method, result, state: instanceParameters || {}, hashParameters, args, ...rest };
  }

  private async handlePrefetchRedirectUri(): Promise<void> {
    if (!document) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const redirectHtml = document.createElement("link");
      redirectHtml.href = this.config.redirect_uri;
      if (window.location.origin !== new URL(this.config.redirect_uri).origin) redirectHtml.crossOrigin = "anonymous";
      redirectHtml.type = "text/html";
      redirectHtml.rel = "prefetch";
      const resolveFn = () => {
        this.isInitialized = true;
        resolve();
      };
      try {
        if (redirectHtml.relList && redirectHtml.relList.supports) {
          if (redirectHtml.relList.supports("prefetch")) {
            redirectHtml.onload = resolveFn;
            redirectHtml.onerror = () => {
              reject(new Error(`Please serve redirect.html present in serviceworker folder of this package on ${this.config.redirect_uri}`));
            };
            document.head.appendChild(redirectHtml);
          } else {
            // Link prefetch is not supported. pass through
            resolveFn();
          }
        } else {
          // Link prefetch is not detectable. pass through
          resolveFn();
        }
      } catch (err) {
        resolveFn();
      }
    });
  }
}

export default CustomAuth;
