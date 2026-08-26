# Challenge 6: The Trojan Tool

FROM node:18-alpine AS builder
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .

FROM node:18-alpine
RUN apk add --no-cache socat
WORKDIR /app
COPY --from=builder /app /app
RUN adduser -D ctf
RUN chown -R ctf:ctf /app
USER ctf

ENV CTF_FLAG=CTF{c0mm4nd_1nj3ct10n_v14_d14gn0st1cs}
EXPOSE 1337

ENTRYPOINT ["/bin/sh", "-c", "socat TCP-LISTEN:1337,reuseaddr,fork EXEC:'node index.js'"]
