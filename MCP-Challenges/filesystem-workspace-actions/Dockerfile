FROM python:3.11-alpine

# Install socat to expose standard IO over TCP
RUN apk add --no-cache socat

# Create a non-root user and group
RUN addgroup -S ctf && adduser -S ctf -G ctf

# Create necessary directories
RUN mkdir -p /home/ctf/workspace /home/ctf/app
WORKDIR /home/ctf/app

# Copy the vulnerable server script
COPY vulnerable-mcp-server-filesystem-workspace-actions-mcp.py .

# Create the CTF flag
# Permissions: ctf user can read it, but it's not inside the isolated workspace
RUN echo "CTF{w0rkspac3_3scap3_rc3_succ3ss}" > /home/ctf/flag.txt
RUN chmod 444 /home/ctf/flag.txt

# Set permissions for the working directory
RUN chown -R ctf:ctf /home/ctf
RUN chmod 750 /home/ctf/app/vulnerable-mcp-server-filesystem-workspace-actions-mcp.py

# Switch to the non-root user
USER ctf

# Expose the TCP port
EXPOSE 1337

# Run socat: listening on 1337, executing the python script with the workspace dir, redirecting stdin/stdout
ENTRYPOINT ["/bin/sh", "-c", "socat TCP-LISTEN:1337,reuseaddr,fork EXEC:'python3 vulnerable-mcp-server-filesystem-workspace-actions-mcp.py /home/ctf/workspace'"]
