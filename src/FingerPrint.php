<?php
namespace Dikiwidia\FpSolution;

use Exception;

class FingerPrint
{
    public static function getData($ipAddress, $port, $key = 0)
    {
        try {
            $isIPv4 = filter_var($ipAddress, FILTER_VALIDATE_IP);
            $isPort = !is_nan($port);
            if ($isIPv4 && $isPort){
                $connect = fsockopen($ipAddress, $port, $errno, $errstr, 1);
                if ($connect) {
                    $soapRequest = "<GetAttLog><ArgComKey xsi:type=\"xsd:integer\">" . $key . "</ArgComKey><Arg><PIN xsi:type=\"xsd:integer\">All</PIN></Arg></GetAttLog>";
                    $newLine = "\r\n";
                    fputs($connect, "POST /iWsService HTTP/1.0" . $newLine);
                    fputs($connect, "Content-Type: text/xml" . $newLine);
                    fputs($connect, "Content-Length: " . strlen($soapRequest) . $newLine . $newLine);
                    fputs($connect, $soapRequest . $newLine);
                    $buffer = "";
                    while($response = fgets($connect, 1024)) {
                        $buffer = $buffer . $response;
                    }
                    $buffer = self::parseData($buffer, "<GetAttLogResponse>","</GetAttLogResponse>");
                    $buffer = explode("\r\n", $buffer);
                    $datas = [];
                    for($i = 0; $i < count($buffer); $i++){
                        $resource = self::parseData($buffer[$i], "<Row>", "</Row>");
                        if ($resource != ""){
                            $data = [];
                            $data['pin'] = self::parseData($resource, "<PIN>", "</PIN>");
                            $data['datetime'] = self::parseData($resource, "<DateTime>", "</DateTime>");
                            $data['verified'] = self::parseData($resource, "<Verified>", "</Verified>");
                            $data['status'] = self::parseData($resource, "<Status>", "</Status>");
                            array_push($datas, $data);
                        }
                    }
                    return $datas;
                } else {
                    throw new Exception('Can not make connection to machine !', 403);
                }
            } else {
                throw new Exception('IP Address / Port not found !', 404);
            }
        } catch (\Exception $err) {
            return $err;
        }
    }

    private static function parseData($data, $p1, $p2)
    {
        $data = " ".$data;
        $result = "";
        $first = strpos($data, $p1);
        if ($first != "") {
            $last = strpos(strstr($data, $p1), $p2);
            if ($last != "") {
                $result = substr($data, $first + strlen($p1), $last - strlen($p1));
            }
        }
        return $result;
    }
}

