require('dotenv').config();
const express = require('express');
const { ethers } = require('ethers');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(cors());
app.use(express.json());

// ★追加：Render等のプロキシ環境下でクライアントの正しいIPを取得するために必須
// これがないとロードバランサーのIPが判定され、1人が連打すると全ユーザーがロックされます
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
    "function getSupportedTokens() view returns (address[])"
];

const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, provider);

async function retryCall(fn, name = "Request", retries = 3) {
    for (let i = 0; i < retries; i++) {
        try {
            return await fn();
        } catch (err) {
            console.error(`[${name}] Attempt ${i + 1} failed:`, err.message);
            if (i === retries - 1) throw err;
            await new Promise(r => setTimeout(r, 2000));
        }
    }
}

app.post('/get-signature', signatureLimiter, async (req, res) => {
    try {
        const { userAddress, fromToken, toToken, fromAmount, nonce } = req.body;

        if (!userAddress || !fromToken || !toToken || !fromAmount || !nonce) {
            return res.status(400).json({ error: "Missing parameters" });
        }

        const cleanUser = ethers.getAddress(userAddress);
        const cleanFrom = ethers.getAddress(fromToken);
        const cleanTo = ethers.getAddress(toToken);
        const fromAmountBI = BigInt(fromAmount);

        // ★修正：6つの独立したRPC通信を Promise.all で並列実行し、待機時間を大幅に削減
        const [
            isDepositAllowed,
            isWithdrawAllowed,
            fromRateRaw,
            toRateRaw,
            maxSwapUSDRaw,
            actualStockRaw
        ] = await Promise.all([
            retryCall(() => contract.canDeposit(cleanFrom), "checkDeposit"),
            retryCall(() => contract.canWithdraw(cleanTo), "checkWithdraw"),
            retryCall(() => contract.tokenRates(cleanFrom), "getFromRate"),
            retryCall(() => contract.tokenRates(cleanTo), "getToRate"),
            retryCall(() => contract.maxSwapAmountUSD(), "getMaxSwap"),
            retryCall(() => contract.getStock(cleanTo), "getStock")
        ]);

        if (!isDepositAllowed) {
            return res.status(400).json({ error: "This element cannot be used as a catalyst.\n（この素材は錬成陣に捧げることができません）" });
        }
        if (!isWithdrawAllowed) {
            return res.status(400).json({ error: "This element cannot be extracted from the array.\n（この素材は錬成陣から抽出できません）" });
        }

        // 1. レート取得（18桁整数）
        const fromRate = BigInt(fromRateRaw);
        const toRate = BigInt(toRateRaw);

        if (toRate === 0n) return res.status(400).json({ error: "Invalid toToken rate" });

        // 2. スワップ上限チェック
        const fromAmountUSD = (fromAmountBI * fromRate) / BigInt(1e18);
        const maxSwapUSD = BigInt(maxSwapUSDRaw);

        if (fromAmountUSD > maxSwapUSD) return res.status(400).json({ error: "Exceeds max swap amount\n スワップ最大取引数量エラー" });

        // 3. 数量計算と在庫チェック
        const toAmountBI = (fromAmountBI * fromRate) / toRate;
        const actualStock = BigInt(actualStockRaw);

        // ログ用のフォーマット
        const fromReadable = ethers.formatUnits(fromAmountBI, 18);
        const toReadable = ethers.formatUnits(toAmountBI, 18);
        const stockReadable = ethers.formatUnits(actualStock, 18);

        if (actualStock < toAmountBI) {
            console.log(`Insufficient Stock: Required ${toReadable} > Available ${stockReadable}`);
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
        const signature = await wallet.signMessage(ethers.toBeArray(messageHash));

        console.log(`Success: Generated signature for ${fromReadable} -> ${toReadable}`);

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
