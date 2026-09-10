# 移动介质证物核验报告

- 案件编号：A-2026-0917
- 证物标识：USB-KINGSTON-64G-03
- 清单 ID：`1836a3fff6b6492fba752d72e9230758`
- lineage：`848607702ed84ded95c815dcf5570402`
- 采集时间（本地 Asia/Shanghai）：2026-09-01T09:30:00+08:00
- 操作者：赵工(GZ-088)
- 清单状态：sealed，封存时间：2026-09-02T08:30:00+00:00
- 验证编号：`1a632db97ac24a74821cc826e1baba23`
- 重新采集时间：2026-09-05T07:00:00+00:00

## 核验结论：❌ 不通过

| 项目 | 数量 |
|---|---:|
| 基线条目 | 6 |
| 重采条目 | 5 |
| 新增 | 2 |
| 缺失 | 3 |
| 内容变化 | 1 |
| 改名候选 | 2 |
| 时间异常 | 2 |
| 分块损坏文件 | 1 |
| 元数据异常 | 0 |
| 交接问题 | 0 |
| Merkle/链问题 | 0 |
| 版本链问题 | 0 |

## 新增文件
- `DCIM/IMG_0002_备份.jpg`  sha256=`7f18ea9027286f88…`  2512992 字节
- `RECYCLER/stealer.exe`  sha256=`2ac82c1ceec8ea36…`  45056 字节

## 缺失文件
- `DCIM/IMG_0001.jpg`  sha256=`56f20ac2aee40a83…`
- `DCIM/IMG_0002.jpg`  sha256=`7f18ea9027286f88…`
- `VIDEO/REC_0001.mp4`  sha256=`484f41cfaf7b60f6…`

## 无法解释的新增/缺失
- [high] UNEXPLAINED_ADD `RECYCLER/stealer.exe`：重采数据出现基线中不存在的文件（且无哈希一致的改名候选）
- [high] UNEXPLAINED_MISSING `DCIM/IMG_0001.jpg`：基线文件在重采数据中缺失（且无哈希一致的改名候选）
- [high] UNEXPLAINED_MISSING `VIDEO/REC_0001.mp4`：基线文件在重采数据中缺失（且无哈希一致的改名候选）

## 改名候选
- `DCIM/IMG_0001.jpg` → `DCIM/IMG_0002_备份.jpg`（medium，相似度 0.865，哈希一致：False）
- `DCIM/IMG_0002.jpg` → `DCIM/IMG_0002_备份.jpg`（high，相似度 0.919，哈希一致：True）

## 内容变化
- `Images/banner.png`：`f0ad3bf969339c20…` → `c3d8424492edd930…`

## 时间异常
- [warning] MTIME_IN_FUTURE RECYCLER/stealer.exe：文件修改时间晚于当前时间
- [warning] MTIME_AFTER_COLLECT RECYCLER/stealer.exe：文件修改时间晚于重新采集时间

## 分块损坏范围
- `Images/banner.png` 分块大小 4096：块 10-11（字节约 40960-49151）, 块 64-64（字节约 262144-266239）

## Merkle 根

- 封存根：`4d96ce40a55054a25ae502ee584a2c944b8ded072a4a4664ffbfefc47960c93b`
- 基线重算根：`4d96ce40a55054a25ae502ee584a2c944b8ded072a4a4664ffbfefc47960c93b`
- 重采数据根：`a4f2ba43d9f6137a0c1dd095c9113faa31d9e9693a4b820e3fa471f0111db874`

## 审计哈希链

- 完整性：完好
- 事件数：8
- 末事件哈希：`14b6de70c719a116fdcec72d06655983a5e7cfaa0fe602430fbac5d090ce4a33`
