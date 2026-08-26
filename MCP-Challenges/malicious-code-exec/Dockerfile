# Build Stage
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .

# Release Stage
FROM node:18-alpine
RUN apk add --no-cache socat && adduser -D ctf
WORKDIR /home/ctf/app
COPY --from=builder /app /home/ctf/app

# Set permissions
RUN chown -R ctf:ctf /home/ctf && chmod -R 750 /home/ctf/app

# Set the Flag in the Environment
ENV CTF_FLAG="CTF{3v4l_rce_1s_4lw4ys_d4ng3r0us}"

USER ctf
EXPOSE 1337

# Expose via TCP socket 1337
ENTRYPOINT ["/bin/sh", "-c", "socat TCP-LISTEN:1337,reuseaddr,fork EXEC:'node index.js'"]
