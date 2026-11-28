FROM python:3.12-bookworm

# Create non-root user
RUN adduser rustcrypto --disabled-password --gecos ""

USER rustcrypto

# Install Rust
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/home/rustcrypto/.cargo/bin:${PATH}"

# Pinned revisions, so that a run can be reproduced. These are the revisions used for the
# results under tests/marvin/ from 2026-11-24 onwards.
#
# `step2.py` is taken from an earlier revision: at MARVIN_TOOLKIT_REV it reads a variable
# that is only set when `-k` is passed, and fails with `NameError: name 'key' is not
# defined` when called with a certificate only, as entrypoint.sh does.
ARG MARVIN_TOOLKIT_REV=7d264ab2b6611b25b95d5dd6bd1590a761c47048
ARG MARVIN_STEP2_REV=3b42df3
ARG TLSFUZZER_REV=51aad6e9ae42f5b045fa9b76129fe0746631784d

# Clone the marvin-toolkit repository. tlsfuzzer is cloned here at a pinned revision;
# step0.sh leaves an existing checkout alone.
RUN cd $HOME \
    && git clone https://github.com/tomato42/marvin-toolkit.git \
    && cd marvin-toolkit \
    && git checkout --quiet $MARVIN_TOOLKIT_REV \
    && git checkout --quiet $MARVIN_STEP2_REV -- step2.py \
    && git clone https://github.com/tomato42/tlsfuzzer.git \
    && git -C tlsfuzzer checkout --quiet $TLSFUZZER_REV \
    && chmod +x *.sh \
    && ./step0.sh
WORKDIR "/home/rustcrypto/marvin-toolkit"

# Generating private keys, ciphertexts, building the harness, should all be done at runtime
COPY --chmod=777 entrypoint.sh ./entrypoint.sh

# The harness source (upstream's, plus a --mode switch for OAEP) and the OAEP ciphertext
# generator, which adds a valid OAEP probe to the toolkit's step2.py.
COPY --chown=rustcrypto harness/main.rs ./example/rust-crypto/src/main.rs
COPY --chown=rustcrypto --chmod=755 oaep_step2.py ./oaep_step2.py

ENTRYPOINT ["./entrypoint.sh"]
