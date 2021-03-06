####################################################################################################
## Builder
####################################################################################################
FROM rust:1.60 as builder

RUN rustup target add x86_64-unknown-linux-musl
RUN apt update && apt install -y musl-tools musl-dev
RUN update-ca-certificates

# Create appuser
# ENV USER=strongholdms
# ENV UID=10001

# RUN adduser \
#    --disabled-password \
#    --gecos "" \
#    --home "/nonexistent" \
#    --shell "/sbin/nologin" \
#    --no-create-home \
#    --uid "${UID}" \
#    "${USER}"

WORKDIR /strongholdms

ADD src src
ADD Cargo.toml Cargo.toml

RUN cargo build --target x86_64-unknown-linux-musl --release

####################################################################################################
## Final image
####################################################################################################
FROM scratch

# COPY --from=builder /etc/passwd /etc/passwd
# COPY --from=builder /etc/group /etc/group

WORKDIR /strongholdms

COPY --from=builder /strongholdms/target/x86_64-unknown-linux-musl/release/strongholdms ./

# USER strongholdms:strongholdms

CMD ["/strongholdms/strongholdms"]