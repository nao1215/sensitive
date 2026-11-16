| Case | masq v0.2.3 output fragment | embargo output fragment |
|---|---|---|
| nested_struct | `"user":{"ID":"u123","Email":"[REDACTED]"}` | `"user":{"ID":"u123","Email":"[REDACTED]"}` |
| message | `"msg":"[REDACTED]"` | `"msg":"login failed for [REDACTED]"` |
| attribute_key | `"alice@example.com":"ok"` | `"[REDACTED]":"ok"` |
| group_name | `"alice@example.com":{"status":"ok"}` | `"[REDACTED]":{"status":"ok"}` |
| marshal_json | `"email":"alice@example.com"` | `"email":"[REDACTED]"` |
| wrapped_error | `"error":"[REDACTED]"` | `"error":"request failed: [REDACTED]"` |
| opaque_password | `"Password":"[REDACTED]"` | `"Password":"[REDACTED]"` |
| secret_wrapper | `"Password":"[REDACTED]"` | `"Password":"[REDACTED]"` |
| tag_or_key | `"Recovery":"[REDACTED]"` | `"Recovery":"[REDACTED]"` |
| valid_card | `"card":"[REDACTED]"` | `"card":"[REDACTED]"` |
| invalid_luhn | `"order":"[REDACTED]"` | `"order":"[REDACTED]"` |
| map | `"data":{"count":17,"email":null,"password":null}` | `"data":{"count":17,"email":"[REDACTED]","password":"[REDACTED]"}` |
