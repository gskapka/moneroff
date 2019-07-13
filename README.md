## :troll_face: Moneroff

__❍__ An offline Monero key generator & transaction signer in Rust.

&nbsp;

***

### :clipboard: To Do:

- [x] Add key generation ability.
- [x] Add CLI arg support w/ docopt.
- [x] Add key set generation from existing.
- [x] Make sensible key type so that sizes are enforced!
- [ ] Have way to save and load from encrypted key file(s).
- [ ] how does monero encrypt the files (if it does?)
- [ ] Make work w/ multiple keys
- [ ] Use inquirerjs style menu (rustbox?) for picking which key to sign with.
- [ ] Add ability to add/rm keys (make latter require p-word of that key!).

&nbsp;

***

### :wrench: Build it:

__`cargo +nightly build --release`__
Note the use of nightly since we're using the __`try_trait`__ in order to unwrap options into Results and thus use the __`?`__ operator on both in the same fxn.

&nbsp;

***

### :school_satchel: Test it:

__`cargo +nightly test`__

***

### :nut_and_bolt: Resources:

__`Monero Related`__

 - __[Zero to Monero PDF.](https://www.getmonero.org/library/Zero-to-Monero-1-0-0.pdf)__
 - __[Monero seed word list.](https://github.com/monero-project/monero/blob/master/src/mnemonics/english.h)__
 - __[Unofficial Monero Docs.](https://monerodocs.org/)__
 - __[Rust Lib for ED25519 curve stuff.](https://github.com/dalek-cryptography/curve25519-dalek)__
 - __[Cryptonote Address Generator & seed work explanation.](https://xmr.llcoins.net/addresstests.html)__

&nbsp;
