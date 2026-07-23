require('dotenv').config();
const express = require('express');
const { ethers } = require('ethers');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();

// ★改修1: CORS（アクセス制限）を環境変数から取得してホワイトリスト化
const allowedOrigins = process.env.FRONTEND_URL
    ? process.env.FRONTEND_URL.split(',').map(url => url.trim())
    : ["http://localhost:3000"];

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('CORSエラー: 許可されていないURLからのアクセスです'));
        }
    },
    methods: ["GET", "POST"]
};

app.use(cors(corsOptions));
app.use(express.json());
app.set('trust proxy', 1);

const signatureLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1分間
    max: 10, // 1つのIPアドレスにつき10回まで
    message: { error: "Too many signature requests. Please try again later.\n（署名リクエストが多すぎます。しばらく待ってから再試行してください）" },
    standardHeaders: true,
    legacyHeaders: false,
});

const PRIVATE_KEY = process.env.PRIVATE_KEY;
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;
const RPC_URL = process.env.RPC_URL_ROBINHOOD || "https://rpc.testnet.chain.robinhood.com";

const provider = new ethers.JsonRpcProvider(RPC_URL);

let pk = PRIVATE_KEY;
if (pk && !pk.startsWith('0x')) pk = '0x' + pk;
const wallet = new ethers.Wallet(pk, provider);

// ==========================================
// サーバー起動確認（プレウォーム）用 API
// ==========================================
app.get('/api/health', (req, res) => {
    res.status(200).json({ status: "ok", message: "Swap Server is awake!" });
});

const ABI = [
    "function canDeposit(address) view returns (bool)",
    "function canWithdraw(address) view returns (bool)",
    "function tokenRates(address) view returns (uint256)",
    "function maxSwapAmountUSD() view returns (uint256)",
    "function getStock(address) view returns (uint256)",
    "function nonces(address) view returns (uint256)",
    "function getSupportedTokens() view returns (address[])",
    "function isPaused() view returns (bool)"
];

const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, provider);

async function retryCall(fn, name = "Request", retries = 3) {
    for (let i = 0; i < retries; i++) {
        try { return await fn(); }
        catch (err) {
            console.error(`[${name}] Attempt ${i + 1} failed:`, err.message);
            if (i === retries - 1) throw err;
            await new Promise(r => setTimeout(r, 2000));
        }
    }
}

// ★改修3: RPC負荷対策（全体設定のキャッシュ化）
// maxSwapAmountUSD と isPaused はユーザーごとに変わらないため、1分に1回だけ取得して使い回す
let systemCache = {
    maxSwapUSD: 0n,
    isPaused: false,
    lastUpdated: 0
};

async function updateSystemCache() {
    try {
        const [maxSwap, paused] = await Promise.all([
            retryCall(() => contract.maxSwapAmountUSD(), "getMaxSwap"),
            retryCall(() => contract.isPaused(), "checkPause")
        ]);
        systemCache.maxSwapUSD = BigInt(maxSwap);
        systemCache.isPaused = paused;
        systemCache.lastUpdated = Date.now();
    } catch (e) {
        console.error("Cache update failed:", e.message);
    }
}
// 起動時に1回取得し、その後は1分間隔で更新
updateSystemCache();
setInterval(updateSystemCache, 60 * 1000);

app.post('/get-signature', signatureLimiter, async (req, res) => {
    try {
        const { userAddress, fromToken, toToken, fromAmount, nonce, cfToken } = req.body;

        if (!userAddress || !fromToken || !toToken || !fromAmount || nonce === undefined) {
            return res.status(400).json({ error: "Missing parameters" });
        }

        if (!cfToken) {
            return res.status(400).json({ error: "Bot verification token is missing. / 検証トークンが見つかりません。" });
        }
        try {
            const cfFormData = new URLSearchParams();
            cfFormData.append('secret', process.env.TURNSTILE_SECRET_KEY);
            cfFormData.append('response', cfToken);

            const cfResponse = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
                method: 'POST',
                body: cfFormData,
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });
            const cfData = await cfResponse.json();
            if (!cfData.success) {
                return res.status(403).json({ error: "Bot verification failed. / セキュリティ検証に失敗しました。" });
            }
        } catch (cfErr) {
            console.error("Turnstile API Error:", cfErr.message);
            return res.status(500).json({ error: "Internal security verification timeout. / 検証サーバー通信エラー" });
        }

        // キャッシュのデータを使用してPauseをチェック
        if (systemCache.isPaused) {
            return res.status(400).json({ error: "System is currently paused for maintenance.\n（現在システムはメンテナンス等により一時停止中です）" });
        }

        const cleanUser = ethers.getAddress(userAddress);
        const cleanFrom = ethers.getAddress(fromToken);
        const cleanTo = ethers.getAddress(toToken);
        const fromAmountBI = BigInt(fromAmount);

        // ★改修2・3: 必要な情報（個人・トークンごと）のみをブロックチェーンから取得し、Nonceも検証する
        const [
            isDepositAllowed,
            isWithdrawAllowed,
            fromRateRaw,
            toRateRaw,
            actualStockRaw,
            currentNonceRaw // ★追加: コントラクト側の正しいNonceを取得
        ] = await Promise.all([
            retryCall(() => contract.canDeposit(cleanFrom), "checkDeposit"),
            retryCall(() => contract.canWithdraw(cleanTo), "checkWithdraw"),
            retryCall(() => contract.tokenRates(cleanFrom), "getFromRate"),
            retryCall(() => contract.tokenRates(cleanTo), "getToRate"),
            retryCall(() => contract.getStock(cleanTo), "getStock"),
            retryCall(() => contract.nonces(cleanUser), "getNonce") // ★追加
        ]);

        if (!isDepositAllowed) return res.status(400).json({ error: "This element cannot be used as a catalyst." });
        if (!isWithdrawAllowed) return res.status(400).json({ error: "This element cannot be extracted from the array." });

        // ★改修2: Nonce（整理券番号）が正しいか厳密にチェック
        if (BigInt(currentNonceRaw) !== BigInt(nonce)) {
            return res.status(400).json({ error: "Invalid transaction sequence (Nonce mismatch). Please refresh the page.\n（トランザクションの順序が不正です。画面を更新してください）" });
        }

        // 1. レート取得（18桁整数）
        const fromRate = BigInt(fromRateRaw);
        const toRate = BigInt(toRateRaw);

        if (toRate === 0n) return res.status(400).json({ error: "Invalid toToken rate" });

        // 2. スワップ上限チェック
        const fromAmountUSD = (fromAmountBI * fromRate) / BigInt(1e18);
        if (fromAmountUSD > systemCache.maxSwapUSD) return res.status(400).json({ error: "Exceeds max swap amount" });

        // 3. 数量計算と在庫チェック
        const toAmountBI = (fromAmountBI * fromRate) / toRate;
        const actualStock = BigInt(actualStockRaw);

        if (actualStock < toAmountBI) {
            const toReadable = ethers.formatUnits(toAmountBI, 18);
            const stockReadable = ethers.formatUnits(actualStock, 18);
            return res.status(400).json({
                error: "Insufficient liquidity",
                message: `在庫不足: 必要量 ${toReadable} / 在庫 ${stockReadable}`
            });
        }

        // 4. 署名作成
        const messageHash = ethers.solidityPackedKeccak256(
            ["address", "address", "address", "uint256", "uint256", "uint256"],
            [cleanUser, cleanFrom, cleanTo, fromAmountBI, toAmountBI, BigInt(nonce)]
        );

        // ★改修1: Ethers.js v6の正しいメソッド (getBytes) を使用
        const signature = await wallet.signMessage(ethers.getBytes(messageHash));

        res.json({
            toAmount: toAmountBI.toString(),
            signature: signature
        });

    } catch (error) {
        console.error("Critical Error:", error);
        res.status(500).json({ error: "Internal server error", detail: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Signer service running on port ${PORT}`));
