# 票根惠游权益清算

永州主场赛季「一张球票 = 四十多家景区通行权益」的后台清算系统，面向三类参与方：

| 角色 | 关心的事 | 系统能力 |
| --- | --- | --- |
| 赛事方 | 票根可信、退票/改赛可追溯 | HMAC 票根签发、场次登记、退票/取消/延期联动冲抵 |
| 景区 | 弱网可核销、口径统一、不替假票买单 | 在线可信核验；离线先签名留存、网络恢复后清单闭合补传；异常入复核 |
| 结算人员 | 不再用表格反复对账、补贴不重不漏 | 哈希链账本、按景区×周结/月结的可复算清算批次、调整单轨迹 |

## 领域口径（`domain.json`）

沿用既有约定并补全：

- **票种**：实名电子票（补贴 50 元/人次）、纸质票根（30 元）、团体票（20 元）。
- **景区**：42 家，分 4 组——A 山水生态（周结）、B 文博场馆（月结）、C 乡村旅游（周结）、D 城市休闲（月结）。B/D 组不接受团体票。
- **权益**：赛季 `YZ-2026`（2026-03-01 ~ 2026-11-30）内，开赛前 72 小时至赛后 168 小时；每景区限 1 次、每票累计 3 个景区。
- **核销结果五态**：有效 / 待补传 / 待复核 / 已撤销 / 已清算。
- **结算周期**：周结（周一 00:00 至周日 24:00，+08:00）、月结（自然月）。
- **离线参数**：时钟容忍 300 秒；清单闭合时限 24 小时；补传宽限 72 小时。

## 防重复补贴与可信链

1. **票根防伪造**：票根载荷由赛事方 HMAC-SHA256 签名，核销先验签再校验赛季/持票人/票种×分组/场次窗口/次数上限。
2. **离线两阶段**：
   - 弱网时设备对 `{网点, 设备, 签名时间, 原始业务键, 票号, 持票人, 票种, 景区, 场次}` 逐条签名留存（待补传）；
   - 网络恢复后提交「设备签名清单 + 记录」，清单签名锚定整批业务键集合，允许分片到达。
3. **去重键**：离线记录 `(设备, 原始业务键)` 唯一；有效权益 `(票号, 景区)` 唯一，线上线下互斥。
4. **时钟**：设备时钟超前超 300 秒、超过 24h 闭合时限或 72h 宽限的，一律进待复核。
5. **冲抵**：票务退款、场次取消、场次延期（按新开赛时间重算窗口，窗口外冲抵）、人工撤销都生成负向调整单；同一核销的同一调整类型幂等。
6. **封账不可变**：必须按周期顺序封账；已封账批次不改写，后置冲抵挂入当前开放周期；迟来事项自动滚入下一周期。批次保存输入指纹与快照哈希，可随时 `/recompute` 复算。
7. **哈希链账本**：签发、核销、判定、退款、取消、延期、撤销、复核裁决、封账全部上链，`prev_hash = SHA256(prev|action|payload)`，篡改任何一条即断链（`/ledger/verify`）。
8. **异常不吞掉**：所有不合格票根进入待复核队列，由复核员裁决，裁决本身留痕。

## 运行

```bash
python3 service.py --check          # 校验 domain.json（42 家景区/口径完整性）
python3 service.py --port 8000      # 启动服务；DB_PATH、ISSUER_SECRET 走环境变量
python3 -m unittest -v              # 38 项测试
```

## 接口一览（角色经 `X-Role` 头标识：issuer / scenic / reviewer / cashier）

| 方法 路径 | 角色 | 说明 |
| --- | --- | --- |
| `GET /health` `GET /domain` | - | 健康检查、领域口径 |
| `POST /issuer/tickets` | issuer | 票根签发，返回 HMAC 签名 |
| `POST /issuer/matches` | issuer | 场次登记（开赛时间） |
| `POST /issuer/tickets/{code}/refund` | issuer | 退票，联动冲抵 |
| `POST /issuer/matches/{code}/cancel` | issuer | 场次取消 |
| `POST /issuer/matches/{code}/postpone` | issuer | 场次延期（新开赛时间） |
| `POST /devices` | scenic | 设备注册并绑定唯一景区 |
| `POST /scenic/redeem` | scenic | 在线可信核验 |
| `POST /scenic/offline/manifest` | scenic | 设备签名清单闭合 |
| `POST /scenic/offline/upload` | scenic | 离线记录补传（顺序无关、重放幂等） |
| `GET /scenic/rights?ticket=` | scenic | 票的权益轨迹 |
| `GET /reviews` | reviewer | 待复核队列 |
| `POST /reviews/{id}/resolve` | reviewer | 通过补占 / 驳回置撤销 |
| `POST /settlement/seal` | cashier | 按景区×周期封账 |
| `GET /settlement/batches[?spot=]` | cashier | 批次列表 |
| `GET /settlement/batches/{id}/recompute` | cashier | 批次复算校验 |
| `POST /settlement/revocations` | cashier | 人工撤销（生成调整单） |
| `GET /ledger/verify` `GET /ledger/events` | cashier | 哈希链校验、事件轨迹 |
| `GET /proof/order-independence` | - | **顺序无关性证明**（见下） |

## 顺序无关性证明

`GET /proof/order-independence` 每次用一份自包含签名夹具（固定密钥的票根、设备记录与清单，含一条同票同景区重复记录、一条票种不符记录），在四个隔离的全新内存库中分别以**原序、逆序、确定性洗牌、先分片再整批重放**补传，比对权益快照哈希：

```json
{
  "identical": true,
  "conclusion": "同一批离线记录无论以何种顺序/重放到达，只产生一次有效权益",
  "digests": {"原序": "8a27…", "逆序": "8a27…", "洗牌": "8a27…", "重复补传": "8a27…"},
  "snapshot": {"valid_rights": [["P-T001","S001"], …], "total_valid": 4,
               "pending_review": [["P-T005","S001"]]}
}
```

四个摘要相同即证明：到达顺序与重放不改变有效权益集合，重复记录判定为「重复」不产生补贴，异常记录始终停在复核队列。

## 文件

- `domain.json` — 赛季/票种/景区分组/补贴/周期口径（单一事实源）
- `core.py` — 领域内核：签名、核验、离线两阶段、复核、调整单、清算批次、哈希链
- `api.py` — HTTP 路由与角色边界
- `service.py` — 启动入口与配置自检
- `test_core.py` / `test_api.py` — 38 项单元与接口测试

> 演示环境的密钥（`ISSUER_SECRET`、设备 secret）与角色头用于说明数据结构；生产应替换为 KMS 下发密钥、设备证书与网关侧鉴权。
