## :trollface: Moneroff

__❍__ An offline Monero key generator & (soon to be) transaction signer in Rust.

&nbsp;

***

### :wrench: Build it:

__`❍ cargo +nightly build --release`__

Note the use of nightly since we're using the __`try_trait`__ in order to unwrap options into Results and thus use the __`?`__ operator on both in the same fxn.

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
- [ ] Have way to save and load from encrypted key file(s).
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
