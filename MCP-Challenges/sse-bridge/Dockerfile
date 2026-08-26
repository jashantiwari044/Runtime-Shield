FROM node:20-slim
WORKDIR /app

# Install dependencies
COPY package.json ./
RUN npm install

COPY server.js ./

EXPOSE 8080

CMD ["node", "server.js"]
