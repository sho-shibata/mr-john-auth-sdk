# mr-john-auth Python SDK

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Supported-009688.svg)](https://fastapi.tiangolo.com/)
[![Version](https://img.shields.io/badge/version-2.0.0-success.svg)](https://github.com/sho-shibata/mr-john-auth-sdk)

**Mr. John エコシステム共通認証基盤 (`mr-john-auth` v2.0)** と子サービス（Stock Research, Diagramonitor 等）をシームレスかつ高セキュリティに統合するための公式 Python / FastAPI 向け認証・認可ガード & HTTP API クライアント SDK です。

---

## 🚀 特徴 (Key Features)

1. **超高速・完全ステートレスなトークン検証 (< 1ms):**
   * 認証基盤へのリクエスト都度問い合わせを行わず、公開 JWKS（`/.well-known/jwks.json`）を非同期メモリキャッシュしてローカルで RS256 署名を検証。
2. **Stale-While-Revalidate 耐障害性 & キャッシュバスティング DoS 防御:**
   * JWKS 再フェッチ時に一時的なネットワーク瞬断が発生しても、既存のキャッシュ済み公開鍵が存在する場合は検証を継続してゼロダウンタイムを維持。
   * 未知の `kid`（キーID）を大量送信する DoS 攻撃を防ぐため、未知キーに対する再フェッチクールダウン機構（5分間）を内蔵。
3. **厳格な Audience (`aud`) 検証 & 動的環境設定 (`configure`):**
   * `MR_JOHN_AUTH_AUDIENCE`（デフォルト: `mr-john-auth`）および設定済みのレガシー `MR_JOHN_CLIENT_ID` に対するマルチオーディエンス検証をサポートし、トークン不正流用を防止しつつ v1.x からの段階的移行に対応。
   * `dotenv` 読み込み順序に依存しない動的環境変数解決と、`mr_john_auth.configure(...)` による明示的なプログラム設定をサポート。
4. **充実した FastAPI 認可ガード (Depends) & v1.x 後方互換性:**
   * `get_current_user`: RS256 JWT 必須認証
   * `get_optional_user`: ゲスト・ログイン両対応エンドポイント向け任意認証
   * `require_claim`: Firebase Auth スタイルの `custom_claims` 検証ガード（Global Admin 自動通過）
   * `require_mfa`: 機密エンドポイントでの TOTP 二要素認証（2FA）ステップアップ強制
   * `require_global_admin`: エコシステム全体管理者（`global_role == "admin"`）専用ガード
   * `require_plan` / `require_role`: v1.x 互換のプラン階層（`free` < `starter` < `pro` < `max` < `enterprise`）・サービス内ロール認可ガード（`services` / `custom_claims` の双方から自動解決、Global Admin 自動通過）
5. **非同期 HTTP API クライアント (`MrJohnAuthClient`):**
   * v2.0 Direct REST API 認証フロー（`login`, `verify_mfa`, `refresh_tokens`, `logout`, `get_user_profile`）および Global Admin ユーザー管理（`list_users`, `get_user`, `update_user`, `revoke_user_sessions`, `delete_user`）を簡潔に実行可能。
   * `async with MrJohnAuthClient(...) as client:` による持続的 TCP/TLS コネクションプーリングに対応。

---

## 📦 インストール方法 (Installation)

### 1. `requirements.txt` への指定（推奨）

最新の安定リリースタグ（`v2.0.0`）を指定してインストールします：

```text
mr-john-auth @ git+https://github.com/sho-shibata/mr-john-auth-sdk.git@v2.0.0
```

> **Note (認証フリー):**  
> 本リポジトリは Public のため、GitHub Deploy Key や Personal Access Token (PAT) などのシークレット設定なしで、Docker ビルド（Cloud Run 等）や GitHub Actions CI から直接 1 行でインストール可能です。

### 2. `pip` コマンドで直接インストール

```bash
pip install "git+https://github.com/sho-shibata/mr-john-auth-sdk.git@v2.0.0"
```

---

## ⚙️ 環境変数・プログラム設定 (Configuration)

### 1. 環境変数による設定
子サービスの `.env` または Cloud Run 環境変数に必要に応じて設定します（デフォルト値で本番認証基盤に接続可能です）：

| 環境変数名 | デフォルト値 | 説明 |
| :--- | :--- | :--- |
| `MR_JOHN_AUTH_API_URL` | `https://auth.api.mr-john-it.com` | 共通認証基盤の API ベース URL |
| `MR_JOHN_AUTH_JWKS_URL` | `{MR_JOHN_AUTH_API_URL}/.well-known/jwks.json` | 公開 JWKS エンドポイント |
| `MR_JOHN_AUTH_ISSUER` | `https://auth.api.mr-john-it.com` | 期待するトークン発行者 (`iss`) |
| `MR_JOHN_AUTH_AUDIENCE` | `mr-john-auth` | 期待するトークン対象者 (`aud`) |
| `MR_JOHN_CLIENT_ID` | `""` | **[任意 / v1.x 互換]** レガシー子サービス Client ID（設定時は `aud` 検証の許容リストや `services` 参照のデフォルト識別子として併用） |
| `MR_JOHN_CLIENT_SECRET` | `""` | **[任意 / v1.x 互換]** Confidential Client 用のクライアントシークレット |

### 2. `configure()` による明示的設定（任意）
アプリケーション起動時にコードから明示的に設定することも可能です：

```python
import mr_john_auth

mr_john_auth.configure(
    api_url="https://auth.api.mr-john-it.com",
    issuer="https://auth.api.mr-john-it.com",
    audience="mr-john-auth",
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
        "custom_claims": user.custom_claims,
    }

@app.get("/api/v1/public-feed")
async def public_feed(user: Optional[AuthUser] = Depends(get_optional_user)):
    if user:
        return {"mode": "personalized", "tier": user.get_claim("tier", "free")}
    return {"mode": "guest"}
```

---

### 2. `require_claim` ガード・2FA・管理者ガード & v1.x 後方互換ガード

v2.0 では Firebase Auth スタイルの `custom_claims` を検証する `require_claim` ガードを推奨しています。既存の v1.x ガード（`require_plan`, `require_role`）も引き続き後方互換として利用可能です。

```python
from fastapi import FastAPI, Depends
from mr_john_auth import (
    AuthUser,
    require_claim,
    require_global_admin,
    require_mfa,
    require_plan,
    require_role,
)

app = FastAPI()

# v2.0 推奨: custom_claims["pro_user"] == True を要求（Global Admin は自動通過）
@app.get("/api/v1/ai/deep-analysis")
async def get_deep_analysis(user: AuthUser = Depends(require_claim("pro_user"))):
    return {"analysis": "Pro-tier AI Market Analysis"}

# v2.0 推奨: custom_claims["tier"] == "enterprise" を要求
@app.get("/api/v1/enterprise/report")
async def get_enterprise_report(user: AuthUser = Depends(require_claim("tier", "enterprise"))):
    return {"report": "Enterprise Report"}

# TOTP 2段階認証が完了しているユーザーのみ実行可能
@app.post("/api/v1/orders/execute")
async def execute_trade(user: AuthUser = Depends(require_mfa)):
    return {"status": "executed"}

# 全体管理者 (global_role == "admin") のみ実行可能
@app.delete("/api/v1/admin/cache")
async def purge_cache(user: AuthUser = Depends(require_global_admin)):
    return {"purged": True}

# v1.x 後方互換: プラン階層・ロールによる認可ガードもそのまま利用可能
@app.get("/api/v1/legacy/pro-feature")
async def legacy_pro_feature(user: AuthUser = Depends(require_plan("pro"))):
    return {"plan": user.get_service_plan()}

@app.post("/api/v1/legacy/signals/publish")
async def publish_signal(user: AuthUser = Depends(require_role(["trader", "analyst"]))):
    return {"published_by": user.id}
```

> **v1.x からの後方互換性について:**  
> `require_plan`, `require_role`, `user.get_service_entitlement()`, `user.get_service_plan()`, `user.get_service_roles()`, `user.has_service_role()`, `user.has_any_service_role()`, `user.has_minimum_plan()`, `user.get_custom_claim()` はすべて v2.0 でも維持されています。JWT 内のレガシー `services` クレームと v2.0 `custom_claims` の双方から透過的に解決されるため、既存コードを変更せずにアップグレードできます。

---

### 3. `MrJohnAuthClient` (v2.0 Direct REST API & Admin クライアント)

`MrJohnAuthClient` は v2.0 の Direct REST API 認証フローおよび Global Admin 向けユーザー管理 API に対応しています。複数回リクエストを行う場合は `async with` によるコネクションプーリングを利用できます。

#### Direct REST API 認証フロー

```python
from mr_john_auth import MrJohnAuthClient

async with MrJohnAuthClient(api_base_url="https://auth.api.mr-john-it.com") as auth_client:
    # 1. メール・パスワードでログイン
    res = await auth_client.login(email="user@example.com", password="your-password")

    # MFA チャレンジが必要な場合
    if res.get("mfa_required"):
        res = await auth_client.verify_mfa(mfa_token=res["mfa_token"], code="123456")

    # 2. 最新プロフィール・カスタムクレーム取得 (GET /api/v1/users/me)
    profile = await auth_client.get_user_profile(user_access_token=res["access_token"])

    # 3. リフレッシュトークンローテーション & ログアウト
    refreshed = await auth_client.refresh_tokens(refresh_token=res["refresh_token"])
    await auth_client.logout(refresh_token=refreshed["refresh_token"])
```

#### Global Admin ユーザー管理

```python
from mr_john_auth import MrJohnAuthClient

async with MrJohnAuthClient(admin_access_token="eyJhbGciOiJSUzI1NiIs...") as admin_client:
    # ユーザー検索・一覧取得
    users = await admin_client.list_users(q="example.com", page=1, per_page=20)

    # 個別ユーザー取得
    user = await admin_client.get_user(user_id="user-uuid-123")

    # 属性・カスタムクレームの更新 (PATCH /api/v1/admin/users/{user_id})
    updated = await admin_client.update_user(
        user_id="user-uuid-123",
        custom_claims={"pro_user": True, "tier": "pro"},
    )

    # 全セッション強制失効 / ユーザー削除
    await admin_client.revoke_user_sessions(user_id="user-uuid-123")
    await admin_client.delete_user(user_id="user-uuid-123")
```

---

### 4. `AuthUser` オブジェクトのプロパティ & メソッド一覧

| プロパティ / メソッド | 型 | 説明 |
| :--- | :--- | :--- |
| `user.id` | `str` | エコシステム共通のユーザー一意 UUID (`sub`) |
| `user.email` | `str` | ユーザーのメールアドレス |
| `user.email_verified` | `bool` | メールアドレス認証済みかどうか |
| `user.display_name` | `Optional[str]` | 表示名 |
| `user.avatar_url` | `Optional[str]` | アバター画像 URL |
| `user.global_role` | `str` | 全体ロール（`user`, `admin`） |
| `user.is_global_admin` | `bool` | 全体管理者（`admin`）かどうか |
| `user.mfa_verified` | `bool` | セッションで TOTP 認証が完了しているか |
| `user.amr` | `List[str]` | 認証方式参照（例: `["pwd", "totp"]`） |
| `user.token_version` | `int` | トークンバージョン (`ver`) |
| `user.custom_claims` | `Dict[str, Any]` | Firebase Auth スタイルのカスタムクレーム辞書 |
| `user.get_claim(key, default)` | `Any` | `custom_claims` から指定キーの値を取得 |
| `user.has_claim(key, expected_value)` | `bool` | `custom_claims[key] == expected_value` を判定（Global Admin は常に `True`） |
| `user.get_service_entitlement(service_id)` | `ServiceEntitlement` | **[v1.x 互換]** プラン・ロール・カスタムクレームの構造化オブジェクトを取得 |
| `user.get_service_plan(service_id)` | `str` | **[v1.x 互換]** 指定サービスにおける契約プラン名（デフォルト: `free`） |
| `user.get_service_roles(service_id)` | `List[str]` | **[v1.x 互換]** 指定サービスにおけるロール一覧 |
| `user.has_service_role(role, service_id)` | `bool` | **[v1.x 互換]** 指定サービスで特定ロールを保持しているか判定 |
| `user.has_any_service_role(roles, service_id)` | `bool` | **[v1.x 互換]** 指定サービスで指定ロール群のいずれかを保持しているか判定 |
| `user.has_minimum_plan(minimum_plan, service_id)` | `bool` | **[v1.x 互換]** 指定サービスのプランが `minimum_plan` 以上か判定 |
| `user.get_custom_claim(key, default, service_id)` | `Any` | **[v1.x 互換]** サービス権限またはトップレベル `custom_claims` から値を取得 |

---

## ⚠️ ステートレス検証と即時権限反映に関する設計ノート

* `get_current_user` は DB 照会を行わない高速ローカル検証（< 1ms）であるため、アカウントの即時停止や権限変更はアクセストークンの有効期限が切れるまでローカル検証を通過します。
* 高額決済や不可逆な操作など、最新 DB 状態の即時確認が必要なエンドポイントでは、`await auth_client.get_user_profile(access_token)` または管理者権限での `await auth_client.get_user(user.id)` を併用してください。

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
