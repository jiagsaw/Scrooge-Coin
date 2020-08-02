# Scrooge-Coin

This is a simulation of `Scrooge Coin`: a simple crypto-currency system using python.

- The system includes 100 users. A designated entity “Scrooge” publishes an append-only ledger that contains all the history of transactions.
- The ledger is a blockchain, where each block contains transactions, its ID, the hash of the block, and a hash pointer to the previous block. 
- The final hash pointer is digitally signed by Scrooge.
- Initially, Scrooge creates 1000 coins and pays each user 10 coins.
- This is a simulation of a network of multiple users: a randomized process of making a transaction, making each transaction reach an arbitrary user.
- Upon detecting any transaction, scrooge verifies it by making sure the coin really belongs to the owner and it has not been spent before.
- If verified, Scrooge adds the transaction to the blockchain. Double spending can only happen before the transaction is published.
- A Merkel Tree is implemented which reflects the change in the blockchain when adding a new block to the blockchain.
- Each recepient uses the Merkel Tree to make sure that the coins are not spent before by the same sender.
- Upon running, each user's data is printed out, followed by the initial blockchain.
- Upon adding a block, the new blockchain is printed out.

**The simulation includes the following options:**

1. Press 't' to Generate a New Random Transaction.
2. Press 'd' to Generate a Double Spending Attack.
3. Press Space to Exit



**Dependencies:**

1. `pip install cryptography`
2. `pip install merklelib`
