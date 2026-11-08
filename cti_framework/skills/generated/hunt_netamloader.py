class HuntNetamLoader:
    def __init__(self):
        self.ioc_hashes = ['4F28622C5E60C01319BF48CF742FE1A5', '514AC0D73B8A1B73488EF5E2E55A75C3', 'E1DC6F1ED193594F2284BE22AE08DFA4', 'F2458ED133F8D0CA19E22C10F577E98E', '67E3617F8709D34F806F8E02BADBA8A5', 'B3C4A635179680EDAFB5D006CF0CFFC6', '9000820D8153C24CD60D53001D3A97B6', 'C86D53392A87DD3F3E62D62C9B92A9BD']

    def run(self):
        for packet in self.network_sniffer.sniff():
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load
                for ioc_hash in self.ioc_hashes:
                    if ioc_hash in payload.hex():
                        self.log(f'Potential NetamLoader activity detected: {packet.summary()}', level='info')
                        self.send_alert(packet, 'Potential NetamLoader activity detected')