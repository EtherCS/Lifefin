# Evaluation of Inflation Attacks on Mysticeti-ACS
```
cd benchmark
pip install -r requirements.txt
```

## Evaluation of Attack without Solution
Run
```
fab inflation
```
By default, it runs **10** nodes (of which **3** are attackers) for **total_time=100** seconds. The attackers will start attacking at **crash_time=20**. After the process finished, run the following command to get figure named *my-inflation.pdf*:
```
fab plot --log-dir='.' --log-prex='attack' --output-path='my-inflation.pdf'
```
> Note that it may take a while to generate the figure as the log files are too large.

## Evaluation of Attack with Solution
Run
```
fab resist
```
By default, it runs **10** nodes (of which **3** are attackers) for **total_time=100** seconds. The attackers will start attacking at **crash_time=20**. The fallback will be triggered at **stuck_round=80**. After the process finished, run the following command to get figure named *my-resist.pdf*:
```
fab plot --log-dir='.' --log-prex='resist' --output-path='my-resist.pdf'
```
> Note: for test, stuck_round should be set appropriately (after the attack begins and before the test is finished). In our test, we find set stuck_round=80 is enough.