import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/extract-eku', methods=['POST'])
def extract_eku():
    data = request.get_json()
    cert = data.get('certificate')

    if not cert:
        return jsonify({'success': False, 'error': 'Certificate not provided'}), 400

    # Save the certificate to a temporary file
    with open("temp_cert.pem", "w") as f:
        f.write(cert)

    # Run the OpenSSL command to extract EKU details
    try:
        result = subprocess.run(
            ['openssl', 'x509', '-in', 'temp_cert.pem', '-noout', '-text'],
            capture_output=True,
            text=True,
            check=True
        )

        # Search for the EKU in the command output
        output = result.stdout
        eku = None
        for line in output.splitlines():
            if "Extended Key Usage" in line:
                eku = line.strip()
                break

        if eku:
            return jsonify({'success': True, 'eku': eku})
        else:
            return jsonify({'success': False, 'error': 'No EKU found in the certificate'}), 400

    except subprocess.CalledProcessError as e:
        return jsonify({'success': False, 'error': 'Error running OpenSSL command: ' + str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
