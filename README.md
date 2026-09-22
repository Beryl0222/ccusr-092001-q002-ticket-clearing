# 票根惠游权益清算

永州主场球票可在 40 余家合作景区兑换游览权益。本系统面向**赛事方、景区、文旅结算人员**三类角色，解决纸质票根伪造、各景区核销口径不一、弱网重复补传、退款/延期/取消后的权益追溯与重复补贴问题，最终按景区与周期给出**可独立复算**的清算批次。

## 快速开始

```bash
pip install -r requirements.txt
python3 service.py --check                      # 校验口径配置与哈希链
python3 -m pytest -q                            # 58 项测试（含乱序等价性证明）
python3 service.py --port 8000 --seed --db data.db   # 带演示数据启动
curl localhost:8000/health
curl localhost:8000/domain
curl localhost:8000/                            # 接口目录
```

`--seed` 会把 `domain.json` 中的 **42 家景区**全部开账、每景区登记一台核销设备，并建立 4 个场次与 8 张演示票。设备密钥在启动日志之外可通过 `seed_demo()` 返回值取得（演示用；生产环境密钥只下发给网点）。

## 领域口径（`domain.json`，三方唯一事实来源）

| 口径 | 取值 |
| --- | --- |
| 票种 | 实名电子票（7 天内限兑 3 次）、纸质票根（3 天内限兑 1 次）、团体票（7 天内限兑 5 次） |
| 景区分组 | 山水名胜/人文古迹/瑶寨民俗/生态度假/城市休闲，每组一个补贴单价（分） |
| 核销结果 | 有效、待补传、待复核、已撤销、已清算 |
| 结算周期 | 周结（ISO 周 `2026-W10`）、月结（`2026-03`），周期自然边界唯一确定 |
| 离线参数 | HMAC-SHA256、时钟容差 300 秒、补传时限 7 天 |

## 核心机制

### 1. 追加式哈希链台账（不可篡改）

配置、设备、场次、票券、核销、重复送达、复核、调整、批次定稿——**一切状态变化都先追加 `events` 事件再更新物化表**。事件以 `sha256(prev_hash ‖ canonical(body))` 串联：

- `GET /audit/state-fingerprint` 查看链尾指纹与完整性；
- 直接改写/删除/插入任何历史事件都会让 `verify_chain()` 断链；
- `POST /admin/rebuild` 清空全部物化表后按台账重放，业务状态逐位复原（测试覆盖）。

### 2. 一张票在赛季、持票人与权益范围内可信核验

在线核验与离线补传共用同一判定：赛季边界 → 持票人 → 票券状态（退款）→ 场次状态（取消/延期）→ 权益窗口（比赛日起 N 天）→ 票种限兑名额。**纸质票根一律先进入人工复核**，确认防伪后才计补贴；票号不存在、持票人不符等异常同样进复核队列而不是被吞掉。

### 3. 弱网两步：先签名留存，再补传（重复/乱序/拆分都只出一次权益）

- `POST /scenic/offline/retain`：设备用预置 HMAC 密钥对 `{设备, 序号, 票号, 持票人, 景区, 签名时间, 原始业务键, 前序签名}` 签名，平台验签后登记为「待补传」；
- `POST /scenic/offline/complete`：恢复网络后补传判定，**接口幂等**；也可用 `submit` 一步到位。
- 三道防重闸：
  1. **内容指纹**：签名负载规范哈希，重复补传只进 `replay_audit`；
  2. **设备序号**：同设备同序号出现不同签名 = 分叉/伪造，转复核；
  3. **原始业务键** `(票号, 景区, business_key)` 唯一：换签名、换序号重发同一入园事实不会产生第二份权益。
- **确定性归并**：一张票的记录按 `(发生时间, 指纹)` 排序竞争限兑名额，结果只取决于记录内容、与到达顺序无关。晚到的更早记录会把已出名额**确定性地冲回**（含已清算名额，走负向冲正），而不是叠加。
- 时钟超前（超容差）→ 复核；超 7 天补传 → 复核；只留存未补传且逾期 → 定时任务 `/admin/sweep` 转复核。

### 4. 退款、延期、取消、人工撤销都不造成重复补贴

- 票务退款 / 比赛取消：该票全部有效记录刚性撤销；
- 场次延期：票券权益窗口整体平移到新比赛日，窗口外已兑记录确定性冲回，窗口内新兑正常出补贴；
- 人工撤销：结算人员可对任一指纹撤销并留痕（操作人、原因、备注）；
- 超出名额属软撤销：当更早的赢家被刚性撤销后，排队记录自动恢复，有效数始终不超限额。

### 5. 按景区与周期可复算的清算批次

`POST /settlement/finalize {scenic, period, period_key}`：

- 每个 `(景区, 周期, 周期键)` 只有一个批次，`batch_id` 由三元组确定性派生，**定稿幂等**，并发定稿有数据库唯一约束兜底；
- 明细含周期内有效核销 + 待结调整（追补/冲正），按 `(类型, 引用)` 排序后规范哈希得 `content_hash`，总额逐笔可加总复算（货币单位：分，冲正为负）；
- 定稿后到达的记录不改历史批次：往期补结以**追补（+）**入下期；清算后退款/取消/撤销/名额重排以**冲正（−）**入下期；
- `GET /settlement/verify` 独立复算每批笔数、金额、内容哈希与归属，并核对哈希链；直接篡改物化金额或台账内容都会被检出。

## 角色与接口

鉴权：赛事方/结算人员用 Bearer 令牌（`EVENT_TOKEN`、`SETTLEMENT_TOKEN` 环境变量可覆盖），景区设备用 `X-Device-Id` + `X-Device-Secret`。

- **赛事方**：`/event/matches`（含 `/postpone`、`/cancel`）、`/event/tickets`（含 `/refund`）、票轨迹 `/tickets/{no}/trail`
- **景区设备**：`/scenic/verify`、`/scenic/offline/{retain,complete,submit}`、`/scenic/offline/stubs`
- **结算人员**：`/admin/scenics`、`/admin/devices`、`/admin/sweep`、`/settlement/reviews` 与 `/decision`、`/settlement/revoke`、`/settlement/finalize(-current)`、`/settlement/batches`、`/settlement/verify`、`/scenics/{name}/summary`、`/audit/replays`、`/audit/state-fingerprint`、`/admin/rebuild`

## 代码结构

| 文件 | 职责 |
| --- | --- |
| `domain.json` / `domain.py` | 三方口径、周期键与边界、时间工具 |
| `crypto.py` | HMAC 签名、规范序列化、内容指纹、哈希链 |
| `store.py` | SQLite：追加事件表（唯一真相）+ 可重建物化表 + 唯一约束 |
| `core.py` | 核验/离线/复核/撤销/确定性归并/台账重放 |
| `clearing.py` | 批次纯函数计算、幂等定稿、追补冲正、独立复算 |
| `seed.py` | 42 景区、设备、场次、票券演示数据 |
| `service.py` | HTTP 路由与三类角色鉴权 |

## 关键不变量（测试即规约）

```bash
python3 -m pytest test_order_invariance.py -v   # 乱序/逆序/拆分/交错到达等价
python3 -m pytest test_concurrency.py -v        # 20 线程并发不产生双份补贴
python3 -m pytest test_clearing.py -v           # 批次复算、冲正追补、篡改检测、重放重建
```

同一批离线记录在正序、逆序、乱序、先留存后补传、留存补传交错五种到达序列下，`state_fingerprint()` 完全一致；同一记录重复补传 N 次只有一条权益，重放次数全部可在 `/audit/replays` 追溯。
