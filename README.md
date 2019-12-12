# Cryptolens Client API for Rust

> This library is currently in a beta release.

This library simplifies access to the [Cryptolens Web API](https://cryptolens.io) from the
Rust programming language.

Several examples are available in the `src/bin` directory. The following commands clone the
repository and runs `example_activate`:

```
$ git clone https://github.com/Cryptolens/cryptolens-rust.git
$ cd cryptolens-rust/
$ cargo run --bin example_activate
```

As long as the library is at version `0.0.X` we are not following semantic versioning. Before
moving to version `0.1.0` at least the following needs to be implemented:

 * [ ] Parse server message when an activation fails, and return an appropriate error.
 * [ ] Add proper management of errors in third-party libraries.
 * [ ] Decide on how to deal with time, should we depend on e.g. the `chrono` crate?
       Or should we just expose the time as an integer and let the user deal with this
       as we do now?
 * [ ] Possibly change capitalization of names to make them more rust-like
