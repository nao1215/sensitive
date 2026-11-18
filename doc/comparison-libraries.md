| Text fixture | godlp v1.2.15 | godlp findings | embargo | embargo findings |
|---|---|---:|---|---:|
| `email alice@example.com` | `email a****@***********` | 1 | `email [REDACTED]` | 1 |
| `credit card 4111111111111111` | `credit card ************1111` | 1 | `credit card [REDACTED]` | 1 |
| `IP 192.0.2.1` | `IP 192.0.2.1` | 1 | `IP [REDACTED]` | 1 |
| `phone 03-1234-5678` | `phone 03-1234-5678` | 0 | `phone [REDACTED]` | 1 |
| `phone 202-555-0123` | `phone 20*-***-**23` | 1 | `phone 202-555-0123` | 0 |
| `credit card 4111111111111112` | `credit card 4111111111111112` | 0 | `credit card 4111111111111112` | 0 |

| Shared event | slog-formatter v1.3.0 PIIFormatter | go-mask v0.6.2 field rules |
|---|---|---|
| flat | `{"card":"4111*******","email":"alic*******","msg":"request"}` | `{"card":"********","email":"********"}` |
| nested | `{"msg":"request","user":"*******"}` | `{"user":{"ID":"u123","Email":"********","Password":"********","Recovery":"********","Count":17}}` |
| map | `{"data":"*******","msg":"request"}` | `{"data":{"card":"********","count":17,"email":"********","password":"********"}}` |
| clean | `{"count":17,"msg":"request","ok":true,"status":"accepted"}` | `{"count":17,"ok":true,"status":"accepted"}` |
| large50 | [Full formatter output](#large50-output) | [Full copy output](#large50-output) |

### large50 output

Formatter:

```json
{"card":"4111*******","email":"alic*******","field0":"clean application value","field1":"clean application value","field10":"clean application value","field11":"clean application value","field12":"clean application value","field13":"clean application value","field14":"clean application value","field15":"clean application value","field16":"clean application value","field17":"clean application value","field18":"clean application value","field19":"clean application value","field2":"clean application value","field20":"clean application value","field21":"clean application value","field22":"clean application value","field23":"clean application value","field24":"clean application value","field25":"clean application value","field26":"clean application value","field27":"clean application value","field28":"clean application value","field29":"clean application value","field3":"clean application value","field30":"clean application value","field31":"clean application value","field32":"clean application value","field33":"clean application value","field34":"clean application value","field35":"clean application value","field36":"clean application value","field37":"clean application value","field38":"clean application value","field39":"clean application value","field4":"clean application value","field40":"clean application value","field41":"clean application value","field42":"clean application value","field43":"clean application value","field44":"clean application value","field45":"clean application value","field46":"clean application value","field47":"clean application value","field5":"clean application value","field6":"clean application value","field7":"clean application value","field8":"clean application value","field9":"clean application value","msg":"request"}
```

Copy:

```json
{"card":"********","email":"********","field0":"clean application value","field1":"clean application value","field10":"clean application value","field11":"clean application value","field12":"clean application value","field13":"clean application value","field14":"clean application value","field15":"clean application value","field16":"clean application value","field17":"clean application value","field18":"clean application value","field19":"clean application value","field2":"clean application value","field20":"clean application value","field21":"clean application value","field22":"clean application value","field23":"clean application value","field24":"clean application value","field25":"clean application value","field26":"clean application value","field27":"clean application value","field28":"clean application value","field29":"clean application value","field3":"clean application value","field30":"clean application value","field31":"clean application value","field32":"clean application value","field33":"clean application value","field34":"clean application value","field35":"clean application value","field36":"clean application value","field37":"clean application value","field38":"clean application value","field39":"clean application value","field4":"clean application value","field40":"clean application value","field41":"clean application value","field42":"clean application value","field43":"clean application value","field44":"clean application value","field45":"clean application value","field46":"clean application value","field47":"clean application value","field5":"clean application value","field6":"clean application value","field7":"clean application value","field8":"clean application value","field9":"clean application value"}
```
