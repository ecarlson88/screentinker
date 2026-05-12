FROM node:20-alpine

RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY server/package*.json ./server/
RUN cd server && npm ci --omit=dev

COPY . .

ENV NODE_ENV=production

EXPOSE 3001 3443

CMD ["node", "server/server.js"]
