FROM ubuntu:22.04

WORKDIR /usr/src/app

COPY . .

RUN apt-get update && apt-get -y install ruby-full wget gcc g++ make

RUN wget https://rubygems.org/rubygems/rubygems-3.6.3.tgz

RUN tar -xvzf rubygems-3.6.3.tgz

RUN gem install jekyll bundler

RUN bundle install

CMD ["bundle", "exec", "jekyll", "serve"]
