## :troll_face: Moneroff

__❍__ An offline monero transaction signer in Rust.

&nbsp;

***

### :clipboard: To Do:

- [ ] Add key generation ability (how does monero encrypt the files (if it does?)
- [ ] Make work w/ multiple keys
- [ ] Use inquirerjs style menu (rustbox?) for picking which key to sign with
- [ ] Add ability to add/rm keys (make latter require p-word of that key!)

&nbsp;

***

### :wrench: Build it:

__`cargo +nightly build --release`__
Note the use of nightly since we're using the __`try_trait`__ in order to unwrap options into Results and thus use the __`?`__ operator on both in the same fxn.
