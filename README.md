# 票根惠游权益清算

该服务面向赛事票务、景区核销与文旅补贴清算。`domain.json` 记录票种、核销结果和结算周期的基础口径，便于合作网点交换一致的数据。

使用 `python3 service.py --check` 检查基础配置，执行 `python3 -m unittest -v` 验证服务身份；运行 `python3 service.py --port 8000` 后可访问 `/health`。
