<?php

use RobRichards\WsePhp\WSASoap;
use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Webmozart\PathUtil\Path;

require_once __DIR__ . '/vendor/autoload.php';

class mySoap extends SoapClient
{
    private string $privateKeyFilePath;
    private string $certFilePath;

    public function __construct(string $privateKeyFilePath, string $certFilePath, $wsdl, array $options = null)
    {
        parent::__construct($wsdl, $options);
        $this->privateKeyFilePath = $privateKeyFilePath;
        $this->certFilePath = $certFilePath;
    }

    /**
     * @param string $request
     * @param string $location
     * @param string $action
     * @param int $version
     * @param null $one_way
     * @return string
     * @throws Exception
     */
    public function __doRequest($request, $location, $action, $version, $one_way = null)
    {
        $dom = new DOMDocument();
        $dom->loadXML($request);

        $objWSA = new WSASoap($dom);
        $objWSA->addAction($action);
        $objWSA->addTo($location);
        $objWSA->addMessageID();
        $objWSA->addReplyTo();

        $dom = $objWSA->getDoc();

        $objWSSE = new WSSESoap($dom, false);
        /* Sign all headers to include signing the WS-Addressing headers */
        $objWSSE->signAllHeaders = TRUE;

        $objWSSE->addTimestamp(3600);

        /* create new XMLSec Key using RSA SHA-1 and type is private key */
        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));

        /* load the private key from file - last arg is bool if key in file (TRUE) or is string (FALSE) */
        $objKey->loadKey($this->privateKeyFilePath, TRUE);

        /* Sign the message - also signs appropriate WS-Security items */
        $objWSSE->signSoapDoc($objKey);

        /* Add certificate (BinarySecurityToken) to the message and attach pointer to Signature */
        $token = $objWSSE->addBinaryToken(file_get_contents($this->certFilePath));
        $objWSSE->attachTokentoSig($token);

        $request = $objWSSE->saveXML();
        $f = fopen('debug.txt', 'wb');
        fwrite($f, print_r($request, true));
        fclose($f);
        return parent::__doRequest($request, $location, $action, $version);
    }
}

$privateKeyFilePath = Path::join(__DIR__, '.config', 'private.pem');
$certFilePath = Path::join(__DIR__, '.config', 'cert.crt');

$soap = new mySoap(
    $privateKeyFilePath,
    $certFilePath,
    'https://ec.europa.eu/taxation_customs/vies/checkVatTestService.wsdl',
    array(
        'soap_version' => SOAP_1_1,
        'trace' => 1,
        'exceptions' => 0,
    ));
$array = array(
    "countryCode" => 'FR',
    "vatNumber" => '100',
);

//print_r($soap->__getFunctions());
//exit;
try {
    $out = $soap->checkVat($array);
    var_dump($out);
} catch (SoapFault $fault) {
    var_dump($fault);
}