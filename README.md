## :trollface: Moneroff

__❍__ An offline Monero key generator & (soon to be) transaction signer in Rust.

&nbsp;

***

### :beginner: Use it:
```
❍ Monero Key Generator ❍

    Copyright Greg Kapka 2019
    Questions: greg@kapka.co.uk

Usage:  moneroff [-h | --help]
        moneroff generate random
        moneroff generate from <key>

Commands:

    generate random     ❍ Generates a random set of Monero keys
    generate from <key> ❍ Generates a set of Monero keys from given private spend key.

Options:

    -h, --help          ❍ Show this message.
    --key=<key>         ❍ A Monero private spend key in HEX format w/ NO prefix!.

```

&nbsp;

***

### :wrench: Build it:

__`❍ cargo +nightly build --release`__

Note the use of __` + nightly`__ since we're using the __`try_trait`__ in order to unwrap options into Results and thus use the __`?`__ operator on both in the same fxn.

&nbsp;

***

### :school_satchel: Test it:

__`❍ cargo +nightly test`__

&nbsp;

***

### :clipboard: To Do:

- [x] Add key generation ability.
- [x] Add CLI arg support w/ docopt.
- [x] Add key set generation from existing.
- [x] Make sensible key type so that sizes are enforced!
- [ ] Add CI to run the rust tests. (Can even use gitlab CI on github!)
- [ ] Have way to save and load from encrypted key file(s).
- [ ] Use clear-on-drop w/ the struct to clear it from memory when finished w/.
- [ ] how does monero encrypt the files (if it does?)
- [ ] Make work w/ multiple keys
- [ ] Use inquirerjs style menu (rustbox?) for picking which key to sign with.
- [ ] Add ability to add/rm keys (make latter require p-word of that key!).

&nbsp;

***

### :black_nib: Monero Notes:

Monero uses the Edwards25519 Elliptic Curve:

__`−x^2 + y^2 = 1 − (121665/121666) * x^2 * y^2`__

...which has the chosen base-point G:

__`G = (x, -4/5)`__

The prime order __`l`__ of the curve is also chosen by the curve's authors as:

__`l = 2^252 + 27742317777372353535851937790883648493`__

… & so the maximum scalar for this curve is:

__`7237005577332262213973186563042994240857116359379907606001950938285454250989`__

&nbsp;

***

### :nut_and_bolt: Resources:

__`Monero Related: `__

 - __[Zero to Monero PDF.](https://www.getmonero.org/library/Zero-to-Monero-1-0-0.pdf)__
 - __[Monero seed word list.](https://github.com/monero-project/monero/blob/master/src/mnemonics/english.h)__
 - __[Unofficial Monero Docs.](https://monerodocs.org/)__
 - __[Rust Lib for ED25519 curve stuff.](https://github.com/dalek-cryptography/curve25519-dalek)__
 - __[Cryptonote Address Generator & seed work explanation.](https://xmr.llcoins.net/addresstests.html)__

&nbsp;
