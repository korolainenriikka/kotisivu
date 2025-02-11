FROM ubuntu:22.04 AS build-stage

WORKDIR /usr/src/app

COPY . .

# install git for jekyll to understand the .git files etc. are not pages part of the homepage
# https://talk.jekyllrb.com/t/liquid-exception-no-such-file-or-directory-git-rev-parse-head-in--layouts-default-html/1010/9
RUN apt-get update && apt-get -y install ruby-full wget gcc g++ make git

RUN wget https://rubygems.org/rubygems/rubygems-3.6.3.tgz

RUN tar -xvzf rubygems-3.6.3.tgz

RUN gem install jekyll bundler

RUN bundle install

#CMD ["bundle", "exec", "jekyll", "serve", "--host", "0.0.0.0", "--livereload"]
FROM nginx:1.19-alpine

COPY --from=build-stage /usr/src/app/_site/ /usr/share/nginx/html
