FROM python:3.11-slim

# System tools
RUN apt-get update && apt-get install -y \
    nmap nikto whatweb sslscan wafw00f golang-go git curl \
    && rm -rf /var/lib/apt/lists/*

# Go-based tools
ENV PATH="$PATH:/root/go/bin"
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/OJ/gobuster/v3@latest && \
    go install github.com/ffuf/ffuf/v2@latest

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]