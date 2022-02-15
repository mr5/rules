FROM node:14.19.0-alpine3.14

RUN mkdir -p /opt/htdocs/rules
WORKDIR /opt/htdocs/rules
COPY ./ /opt/htdocs/rules
RUN yarn --production

EXPOSE 3000
ENTRYPOINT ["node", "index.js"]
