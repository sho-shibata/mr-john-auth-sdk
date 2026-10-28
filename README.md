# mr-john-auth Python SDK

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Supported-009688.svg)](https://fastapi.tiangolo.com/)

**Mr. John エコシステム共通認証基盤 (`mr-john-auth`)** と子サービス（Stock Research, Diagramonitor 等）をシームレスかつ高セキュリティに統合するための公式 Python / FastAPI 向け認証・認可 SDK です。

---

## 🚀 特徴 (Key Features)

1. **超高速・完全ステートレスなトークン検証 (< 1ms):**
   * 認証基盤へのリクエスト都度問い合わせを行わず、公開 JWKS（`/.well-known/jwks.json`）を非同期メモリキャッシュしてローカルで RS256 署名を検証。
2. **キャッシュバスティング DoS 防御:**
   * 未知の `kid`（キーID）を大量送信する DoS 攻撃を防ぐため、未知キーに対する再フェッチクールダウン機構（5分間）を内蔵。
3. **厳格な Audience (`aud`) 検証:**
   * 他の子サービス向けに発行されたトークンの不正流用（Confused Deputy 攻撃）を自動的に遮断。
4. **宣言的な認可ガード (FastAPI Depends):**
   * `get_current_user`: 基本的な JWT 認証
   * `require_mfa`: 機密エンドポイントでの TOTP 二要素認証（2FA）ステップアップ強制
   * `require_plan`: サブスクリプションプラン（Free / Starter / Pro / Enterprise）の階層別認可ガード
5. **例外マスキングによる情報漏洩防止:**
   * 署名不一致や検証失敗時に内部例外詳細をクライアントへ返さず、一貫した `401 Unauthorized` を返却。

---

## 📦 インストール方法 (Installation)

### 1. `requirements.txt` への指定（推奨）

最新の安定リリースタグ（例: `v1.0.0`）を指定してインストールします：

```text
mr-john-auth @ git+https://github.com/sho-shibata/mr-john-auth-sdk.git@v1.0.0
```

> **Note (認証フリー):**  
> 本リポジトリは Public のため、GitHub Deploy Key や Personal Access Token (PAT) などのシークレット設定なしで、Docker ビルド（Cloud Run 等）や GitHub Actions CI から直接 1 行でインストール可能です。

### 2. `pip` コマンドで直接インストール

```bash
pip install "git+https://github.com/sho-shibata/mr-john-auth-sdk.git@v1.0.0"
```

---

## ⚙️ 環境変数設定 (Configuration)

子サービスの `.env` または Cloud Run 環境変数に以下を設定します：

| 環境変数名 | デフォルト値 | 説明 |
| :--- | :--- | :--- |
| `MR_JOHN_CLIENT_ID` | `default-client` | **[必須]** 自サービスの Client ID（例: `stock-research`, `diagramonitor`） |
| `MR_JOHN_AUTH_JWKS_URL` | `https://auth-api.mr-john.dev/.well-known/jwks.json` | 共通認証基盤の公開 JWKS エンドポイント |
| `MR_JOHN_AUTH_ISSUER` | `https://auth.mr-john.dev` | 期待するトークン発行者 (`iss`) |

---

## 💡 使用方法 (Usage)

### 1. 基本的な認証 (`get_current_user`)

```python
from fastapi import FastAPI, Depends
from mr_john_auth import auth_guard, AuthUser

app = FastAPI()

@app.get("/api/v1/profile")
async def read_user_profile(user: AuthUser = Depends(auth_guard.get_current_user)):
    return {
        "user_id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "global_role": user.global_role,
        "mfa_verified": user.mfa_verified,
    }
```

---

### 2. TOTP 二要素認証 (2FA) の強制 (`require_mfa`)

出金や注文執行、パスワード変更などの高機密エンドポイントで TOTP 二要素認証が完了していることを要求します：

```python
from fastapi import FastAPI, Depends
from mr_john_auth import AuthUser, require_mfa

app = FastAPI()

@app.post("/api/v1/orders/execute")
async def execute_trade(user: AuthUser = Depends(require_mfa)):
    # mfa_verified が False の場合、自動的に 403 Forbidden が返却されます
    return {"status": "success", "executed_by": user.email}
```

---

### 3. サブスクリプションプランの階層認可 (`require_plan`)

子サービスのプラン階層（`free` < `starter` < `pro` < `enterprise`）を検証し、上位プランユーザーのみアクセスを許可します：

```python
from fastapi import FastAPI, Depends
from mr_john_auth import AuthUser, require_plan

app = FastAPI()

# "pro" プラン以上（Pro または Enterprise）のみアクセス可能
@app.get("/api/v1/ai/deep-analysis")
async def get_deep_analysis(user: AuthUser = Depends(require_plan("pro"))):
    return {"analysis": "Pro-tier AI Market Analysis"}
```

---

### 4. `AuthUser` オブジェクトのプロパティ

| プロパティ / メソッド | 型 | 説明 |
| :--- | :--- | :--- |
| `user.id` | `str` | エコシステム共通のユーザー一意 UUID (`sub`) |
| `user.email` | `str` | ユーザーのメールアドレス |
| `user.display_name` | `Optional[str]` | 表示名 |
| `user.global_role` | `str` | 全体ロール（`user`, `admin` 等） |
| `user.mfa_verified` | `bool` | セッションで TOTP 認証が完了しているか |
| `user.amr` | `List[str]` | 認証方式参照（例: `["pwd", "totp"]`） |
| `user.get_service_plan("stock-research")` | `str` | 指定サービスにおける契約プラン名（デフォルト: `free`） |
| `user.has_service_role("analyst", "stock-research")` | `bool` | 指定サービスで特定ロールを保持しているか判定 |

---

## 🧪 テストの実行 (Testing)

ローカルで単体テスト（外部通信モック検証）を実行する場合：

```bash
conda activate py313
pip install -e ".[dev]"
pytest tests -v
```

---

## 📄 ライセンス

[MIT License](LICENSE) © 2026 Sho Shibata
