FROM python:3.11

# Set the working directory to /tests
WORKDIR /tests

# Install Node.js and npm (for solc)
RUN apt-get clean && apt-get update && apt-get install -y curl && \
    curl -sL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs

# Install Solidity compiler (solc)
RUN npm install -g solc

# Install Python packages
COPY requirements.txt .
RUN pip3 install -r requirements.txt

COPY . .

RUN npm install

RUN cd lib/js && npm install

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Run script.py when the container launches
ENTRYPOINT [ "/entrypoint.sh" ]
