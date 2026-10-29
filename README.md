# mr-john-auth Python SDK

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Supported-009688.svg)](https://fastapi.tiangolo.com/)
[![Version](https://img.shields.io/badge/version-1.2.0-success.svg)](https://github.com/sho-shibata/mr-john-auth-sdk)

**Mr. John エコシステム共通認証基盤 (`mr-john-auth`)** と子サービス（Stock Research, Diagramonitor 等）をシームレスかつ高セキュリティに統合するための公式 Python / FastAPI 向け認証・認可ガード & HTTP API クライアント SDK です。

---

## 🚀 特徴 (Key Features)

1. **超高速・完全ステートレスなトークン検証 (< 1ms):**
   * 認証基盤へのリクエスト都度問い合わせを行わず、公開 JWKS（`/.well-known/jwks.json`）を非同期メモリキャッシュしてローカルで RS256 署名を検証。
2. **Stale-While-Revalidate 耐障害性 & キャッシュバスティング DoS 防御:**
   * JWKS 再フェッチ時に一時的なネットワーク瞬断が発生しても、既存のキャッシュ済み公開鍵が存在する場合は検証を継続してゼロダウンタイムを維持。
   * 未知の `kid`（キーID）を大量送信する DoS 攻撃を防ぐため、未知キーに対する再フェッチクールダウン機構（5分間）を内蔵。
3. **厳格な Audience (`aud`) 検証 & 動的環境設定 (`configure`):**
   * 他の子サービス向けに発行されたトークンの不正流用（Confused Deputy 攻撃）を自動的に遮断。
   * `dotenv` 読み込み順序に依存しない動的環境変数解決と、`mr_john_auth.configure(...)` による明示的なプログラム設定をサポート。
4. **充実した FastAPI 認可ガード (Depends):**
   * `get_current_user`: RS256 JWT 必須認証
   * `get_optional_user`: ゲスト・ログイン両対応エンドポイント向け任意認証
   * `require_mfa`: 機密エンドポイントでの TOTP 二要素認証（2FA）ステップアップ強制
   * `require_plan`: サブスクリプションプラン（`free` < `starter` < `pro` < `enterprise`）の階層認可ガード（Global Admin 自動通過）
   * `require_role`: サービス内ロール（例: `"trader"`, `["analyst", "editor"]`）の認可ガード（Global Admin 自動通過）
   * `require_global_admin`: エコシステム全体管理者（`global_role == "admin"`）専用ガード
5. **非同期 HTTP API クライアント (`MrJohnAuthClient`):**
   * 子サービスバックエンド（Webhook 等）や管理ツールから、`SERVICE_PERMISSIONS` の登録・更新（Upsert）・取得・削除、`AUTH_CLIENTS` 管理、OAuth 2.0 PKCE 認可コード交換・RTR トークンローテーションを 1 行で実行可能。
   * `async with MrJohnAuthClient(...) as client:` による持続的 TCP/TLS コネクションプーリングに対応。

---

## 📦 インストール方法 (Installation)

### 1. `requirements.txt` への指定（推奨）

最新の安定リリースタグ（`v1.2.0`）を指定してインストールします：

```text
mr-john-auth @ git+https://github.com/sho-shibata/mr-john-auth-sdk.git@v1.2.0
```

> **Note (認証フリー):**  
> 本リポジトリは Public のため、GitHub Deploy Key や Personal Access Token (PAT) などのシークレット設定なしで、Docker ビルド（Cloud Run 等）や GitHub Actions CI から直接 1 行でインストール可能です。

### 2. `pip` コマンドで直接インストール

```bash
pip install "git+https://github.com/sho-shibata/mr-john-auth-sdk.git@v1.2.0"
```

---

## ⚙️ 環境変数・プログラム設定 (Configuration)

### 1. 環境変数による設定
子サービスの `.env` または Cloud Run 環境変数に以下を設定します：

| 環境変数名 | デフォルト値 | 説明 |
| :--- | :--- | :--- |
| `MR_JOHN_CLIENT_ID` | `default-client` | **[必須]** 自サービスの Client ID（例: `stock-research`, `diagramonitor`） |
| `MR_JOHN_CLIENT_SECRET` | `""` | Confidential Client の場合、バックエンド間 API 通信用のクライアントシークレット（`mjc_...`） |
| `MR_JOHN_AUTH_API_URL` | `https://auth-api.mr-john.dev` | 共通認証基盤の API ベース URL |
| `MR_JOHN_AUTH_JWKS_URL` | `{MR_JOHN_AUTH_API_URL}/.well-known/jwks.json` | 公開 JWKS エンドポイント |
| `MR_JOHN_AUTH_ISSUER` | `https://auth.mr-john.dev` | 期待するトークン発行者 (`iss`) |

### 2. `configure()` による明示的設定（任意）
アプリケーション起動時にコードから明示的に設定することも可能です：

```python
import mr_john_auth

mr_john_auth.configure(
    client_id="stock-research",
    client_secret="mjc_your_secret_key",
    api_url="https://auth-api.mr-john.dev",
    issuer="https://auth.mr-john.dev",
)
```

---

## 💡 使用方法 (Usage)

### 1. 基本認証 & 任意認証 (`get_current_user` / `get_optional_user`)

```python
from typing import Optional
from fastapi import FastAPI, Depends
from mr_john_auth import AuthUser, get_current_user, get_optional_user

app = FastAPI()

@app.get("/api/v1/profile")
async def read_user_profile(user: AuthUser = Depends(get_current_user)):
    return {
        "user_id": user.id,
        "email": user.email,
        "entitlement": user.get_service_entitlement(),
    }

@app.get("/api/v1/public-feed")
async def public_feed(user: Optional[AuthUser] = Depends(get_optional_user)):
    if user:
        return {"mode": "personalized", "plan": user.get_service_plan()}
    return {"mode": "guest"}
```

---

### 2. プラン・ロール・2FA・管理者ガード (`require_plan`, `require_role`, `require_mfa`, `require_global_admin`)

```python
from fastapi import FastAPI, Depends
from mr_john_auth import AuthUser, require_mfa, require_plan, require_role, require_global_admin

app = FastAPI()

# Pro プラン以上のみアクセス可能
@app.get("/api/v1/ai/deep-analysis")
async def get_deep_analysis(user: AuthUser = Depends(require_plan("pro"))):
    return {"analysis": "Pro-tier AI Market Analysis"}

# "trader" または "analyst" ロール保持者のみアクセス可能
@app.post("/api/v1/signals/publish")
async def publish_signal(user: AuthUser = Depends(require_role(["trader", "analyst"]))):
    return {"published_by": user.id}

# TOTP 2段階認証が完了しているユーザーのみ実行可能
@app.post("/api/v1/orders/execute")
async def execute_trade(user: AuthUser = Depends(require_mfa)):
    return {"status": "executed"}

# 全体管理者 (global_role == "admin") のみ実行可能
@app.delete("/api/v1/admin/cache")
async def purge_cache(user: AuthUser = Depends(require_global_admin)):
    return {"purged": True}
```

---

### 3. `MrJohnAuthClient` による `SERVICE_PERMISSIONS` 登録・更新・トークン操作

子サービスの決済 Webhook（Stripe 等）やバックエンド BFF から、ユーザーのサービス権限（プラン・ロール・カスタムクレーム）を直接登録・更新（Upsert）・参照できます。複数回リクエストを行う場合は `async with` によるコネクションプーリングも利用可能です：

```python
from mr_john_auth import MrJohnAuthClient

# Confidential Client 認証 (X-Client-Id / X-Client-Secret)
async with MrJohnAuthClient(
    api_base_url="https://auth-api.mr-john.dev",
    client_id="stock-research",
    client_secret="mjc_your_secret_key",
) as auth_client:
    # 1. ユーザーのプラン・ロール・カスタムクレームを登録・更新 (Upsert)
    perm = await auth_client.upsert_user_permission(
        user_id="user-uuid-123",
        plan_tier="pro",
        roles=["member", "trader"],
        custom_claims={"daily_ai_quota": 100},
    )

    # 2. ユーザーの権限情報を取得 / 削除
    current_perm = await auth_client.get_user_permission(user_id="user-uuid-123")
    await auth_client.delete_user_permission(user_id="user-uuid-123")

    # 3. OAuth 2.0 PKCE 認可コード交換 & RTR トークンローテーション
    tokens = await auth_client.exchange_code_for_tokens(
        code="auth_code_from_callback",
        code_verifier="pkce_verifier",
        redirect_uri="https://stock.mr-john.dev/auth/callback",
    )
    refreshed = await auth_client.refresh_tokens(refresh_token=tokens["refresh_token"])
```

---

### 4. `AuthUser` オブジェクトのプロパティ & メソッド一覧

| プロパティ / メソッド | 型 | 説明 |
| :--- | :--- | :--- |
| `user.id` | `str` | エコシステム共通のユーザー一意 UUID (`sub`) |
| `user.email` | `str` | ユーザーのメールアドレス |
| `user.display_name` | `Optional[str]` | 表示名 |
| `user.global_role` | `str` | 全体ロール（`user`, `admin`） |
| `user.is_global_admin` | `bool` | 全体管理者（`admin`）かどうか |
| `user.mfa_verified` | `bool` | セッションで TOTP 認証が完了しているか |
| `user.amr` | `List[str]` | 認証方式参照（例: `["pwd", "totp"]`） |
| `user.get_service_entitlement(service_id)` | `ServiceEntitlement` | プラン・ロール・カスタムクレームの構造化オブジェクトを取得 |
| `user.get_service_plan(service_id)` | `str` | 指定サービスにおける契約プラン名（デフォルト: `free`） |
| `user.get_service_roles(service_id)` | `List[str]` | 指定サービスにおけるロール一覧 |
| `user.has_service_role(role, service_id)` | `bool` | 指定サービスで特定ロールを保持しているか判定 |
| `user.has_any_service_role(roles, service_id)` | `bool` | 指定サービスで指定ロール群のいずれかを保持しているか判定 |
| `user.has_minimum_plan(minimum_plan, service_id)` | `bool` | 指定サービスのプランが `minimum_plan` 以上か判定 |
| `user.get_custom_claim(key, default, service_id)` | `Any` | 指定サービスのカスタムクレーム値を取得 |

---

## ⚠️ ステートレス検証と即時権限反映に関する設計ノート

* `get_current_user` は DB 照会を行わない高速ローカル検証（< 1ms）であるため、アカウントの即時停止やプラン降格はアクセストークンの有効期限（最大5分間）が切れるまでローカル検証を通過します。
* 高額決済や不可逆な操作など、ミリ秒単位での最新 DB 状態確認が必要なエンドポイントでは、`await auth_client.get_user_permission(user.id)` または `await auth_client.get_user_profile(access_token)` を併用してください。

---

## 🧪 テストの実行 (Testing)

ローカルで単体テストおよびカバレッジ検証（95%以上必須）を実行する場合：

```bash
conda activate py313
pip install -e ".[dev]"
pytest tests -v
```

---

## 📄 ライセンス

[MIT License](LICENSE) © 2026 Sho Shibata
