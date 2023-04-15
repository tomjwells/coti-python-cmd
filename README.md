This repository shows how Coti's [Python SDK](https://github.com/coti-io/coti-sdk-python) can be used to perform CMD transactions on the COTI network.

# Prerequisites

Using this Python script requires that Coti's [Python SDK](https://github.com/coti-io/coti-sdk-python) be installed. Their SDK can be installed with

```
pip install coti-wallet
```

The following environment variables should also be set in the .env file:

- `SOURCE_SEED` - Set this to your seed key
- `CURRENCY_HASH` - Set this to the currency hash of your CMD token (it is set to the currency hash for COTI by default)
- `FULL_NODE_BACKEND_ADDRESS` - This is set to one of the Coti nodes by default, but you can change it to another node, for example if you want your own node to process the transaction

Please also add your own destination wallet address into the file `addresses.txt`.

# Usage

To create a single transaction, you may run it with

```
python3 main.py
```

To create multiple transactions, you may run the function `main()` in a loop as shown below:

```
python3 -c "from main import main; [main() for i in range(99)]"
```

Feel free to replace the example number 99 with the number of CMD transactions you wish to perform.
