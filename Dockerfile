# For the build stage, use the official Rust image
FROM rust:latest as rust-build

# Add the source code
ADD src src
ADD Cargo.toml Cargo.toml

# Build
RUN cargo build --release

FROM scratch

# Copy the binary to a minimal Linux OS
COPY --from=rust-build /target/release/strongholdms .

CMD ["./strongholdms"]