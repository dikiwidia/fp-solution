<?php

namespace Dikiwidia\FpSolution;

use Exception;

class FingerPrint
{

    private $ipAddress, $port, $key;

    public function __construct($ipAddress, $port, $key = 0)
    {
        $this->ipAddress = $ipAddress;
        $this->port = $port;
        $this->key = $key;
    }

    /**
     * get all user information from fingerprint machine
     */
    public function getUsers()
    {
        try {
            $isIPv4 = filter_var($this->ipAddress, FILTER_VALIDATE_IP);
            $isPort = !is_nan($this->port);
            if ($isIPv4 && $isPort) {
                $connect = fsockopen($this->ipAddress, $this->port, $errno, $errstr, 1);
                if ($connect) {
                    $soapRequest = "<GetUserInfo><ArgComKey xsi:type=\"xsd:integer\">" . $this->key . "</ArgComKey><Arg><PIN xsi:type=\"xsd:integer\">All</Arg></GetUserInfo>";
                    $newLine = "\r\n";
                    fputs($connect, "POST /iWsService HTTP/1.0" . $newLine);
                    fputs($connect, "Content-Type: text/xml" . $newLine);
                    fputs($connect, "Content-Length: " . strlen($soapRequest) . $newLine . $newLine);
                    fputs($connect, $soapRequest . $newLine);
                    $buffer = "";
                    while ($response = fgets($connect, 1024)) {
                        $buffer = $buffer . $response;
                    }
                    $buffer = self::parseData($buffer, "<GetUserInfoResponse>", "</GetUserInfoResponse>");
                    $buffer = explode("\r\n", $buffer);
                    $datas = [];
                    for ($i = 0; $i < count($buffer); $i++) {
                        $resource = self::parseData($buffer[$i], "<Row>", "</Row>");
                        if ($resource != "") {
                            $data = [];
                            $data['pin'] = self::parseData($resource, "<PIN>", "</PIN>");
                            $data['name'] = self::parseData($resource, "<Name>", "</Name>");
                            $data['password'] = self::parseData($resource, "<Password>", "</Password>");
                            $data['group'] = self::parseData($resource, "<Group>", "</Group>");
                            $data['privilege'] = self::parseData($resource, "<Privilege>", "</Privilege>");
                            $data['card'] = self::parseData($resource, "<Card>", "</Card>");
                            $data['pin2'] = self::parseData($resource, "<PIN2>", "</PIN2>");
                            $data['tz1'] = self::parseData($resource, "<TZ1>", "</TZ1>");
                            $data['tz2'] = self::parseData($resource, "<TZ2>", "</TZ2>");
                            $data['tz3'] = self::parseData($resource, "<TZ3>", "</TZ3>");
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


    /**
     * get user information by id from fingerprint machine
     */
    public function getUser($id)
    {
        try {
            $isIPv4 = filter_var($this->ipAddress, FILTER_VALIDATE_IP);
            $isPort = !is_nan($this->port);
            if ($isIPv4 && $isPort) {
                $connect = fsockopen($this->ipAddress, $this->port, $errno, $errstr, 1);
                if ($connect) {
                    $soapRequest = "<GetUserInfo><ArgComKey xsi:type=\"xsd:integer\">" . $this->key . "</ArgComKey><Arg><PIN xsi:type=\"xsd:integer\">" . $id . "</Arg></GetUserInfo";
                    $newLine = "\r\n";
                    fputs($connect, "POST /iWsService HTTP/1.0" . $newLine);
                    fputs($connect, "Content-Type: text/xml" . $newLine);
                    fputs($connect, "Content-Length: " . strlen($soapRequest) . $newLine . $newLine);
                    fputs($connect, $soapRequest . $newLine);
                    $buffer = "";
                    while ($response = fgets($connect, 1024)) {
                        $buffer = $buffer . $response;
                    }
                    $buffer .= "</GetUserInfoResponse>";
                    $buffer = self::parseData($buffer, "<GetUserInfoResponse>", "</GetUserInfoResponse>");
                    $buffer = explode("\r\n", $buffer);
                    $data = [];
                    for ($i = 0; $i < count($buffer); $i++) {
                        $resource = self::parseData($buffer[$i], "<Row>", "</Row>");
                        if ($resource != "") {
                            $data['pin'] = self::parseData($resource, "<PIN>", "</PIN>");
                            $data['name'] = self::parseData($resource, "<Name>", "</Name>");
                            $data['password'] = self::parseData($resource, "<Password>", "</Password>");
                            $data['group'] = self::parseData($resource, "<Group>", "</Group>");
                            $data['privilege'] = self::parseData($resource, "<Privilege>", "</Privilege>");
                            $data['card'] = self::parseData($resource, "<Card>", "</Card>");
                            $data['pin2'] = self::parseData($resource, "<PIN2>", "</PIN2>");
                            $data['tz1'] = self::parseData($resource, "<TZ1>", "</TZ1>");
                            $data['tz2'] = self::parseData($resource, "<TZ2>", "</TZ2>");
                            $data['tz3'] = self::parseData($resource, "<TZ3>", "</TZ3>");
                        }
                    }
                    return $data;
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

    /**
     * upload user information to fingerprint machine
     */
    public function uploadUser(array $data = ['id' => null, 'name' => null])
    {
        try {
            $isIPv4 = filter_var($this->ipAddress, FILTER_VALIDATE_IP);
            $isPort = !is_nan($this->port);
            if ($isIPv4 && $isPort) {
                $connect = fsockopen($this->ipAddress, $this->port, $errno, $errstr, 1);
                if ($connect) {
                    $soapRequest = "<SetUserInfo><ArgComKey Xsi:type=\"xsd:integer\">" . $this->key . "</ArgComKey><Arg><PIN>" . $data['id'] . "</PIN><Name>" . $data['name'] . "</Name></Arg></SetUserInfo>";
                    $newLine = "\r\n";
                    fputs($connect, "POST /iWsService HTTP/1.0" . $newLine);
                    fputs($connect, "Content-Type: text/xml" . $newLine);
                    fputs($connect, "Content-Length: " . strlen($soapRequest) . $newLine . $newLine);
                    fputs($connect, $soapRequest . $newLine);
                    $buffer = "";
                    while ($response = fgets($connect, 1024)) {
                        $buffer = $buffer . $response;
                    }
                    $buffer = self::parseData($buffer, "<SetUserInfoResponse>", "</SetUserInfoResponse>");
                    $buffer = explode("\r\n", $buffer);
                    $data = [
                        'result' => self::parseData($buffer[1], "<Result>", "</Result>"),
                        'information' => self::parseData($buffer[1], "<Information>", "</Information>")
                    ];
                    return $data;
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

    /**
     * delete user information from fingerprint machine
     */
    public function deleteUser($id)
    {
        try {
            $isIPv4 = filter_var($this->ipAddress, FILTER_VALIDATE_IP);
            $isPort = !is_nan($this->port);
            if ($isIPv4 && $isPort) {
                $connect = fsockopen($this->ipAddress, $this->port, $errno, $errstr, 1);
                if ($connect) {
                    $soapRequest = "<DeleteUser><ArgComKey Xsi:type=\"xsd:integer\">" . $this->key . "</ArgComKey><Arg><PIN>" . $id . "</PIN></Arg></DeleteUser>";
                    $newLine = "\r\n";
                    fputs($connect, "POST /iWsService HTTP/1.0" . $newLine);
                    fputs($connect, "Content-Type: text/xml" . $newLine);
                    fputs($connect, "Content-Length: " . strlen($soapRequest) . $newLine . $newLine);
                    fputs($connect, $soapRequest . $newLine);
                    $buffer = "";
                    while ($response = fgets($connect, 1024)) {
                        $buffer = $buffer . $response;
                    }
                    $buffer = self::parseData($buffer, "<DeleteUserResponse>", "</DeleteUserResponse>");
                    $buffer = explode("\r\n", $buffer);
                    $data = [
                        'result' => self::parseData($buffer[1], "<Result>", "</Result>"),
                        'information' => self::parseData($buffer[1], "<Information>", "</Information>")
                    ];
                    return $data;
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

    /**
     * get attendance log information from fingerprint machine
     */
    public function getAttendance()
    {
        try {
            $isIPv4 = filter_var($this->ipAddress, FILTER_VALIDATE_IP);
            $isPort = !is_nan($this->port);
            if ($isIPv4 && $isPort) {
                $connect = fsockopen($this->ipAddress, $this->port, $errno, $errstr, 1);
                if ($connect) {
                    $soapRequest = "<GetAttLog><ArgComKey xsi:type=\"xsd:integer\">" . $this->key . "</ArgComKey><Arg><PIN xsi:type=\"xsd:integer\">All</PIN></Arg></GetAttLog>";
                    $newLine = "\r\n";
                    fputs($connect, "POST /iWsService HTTP/1.0" . $newLine);
                    fputs($connect, "Content-Type: text/xml" . $newLine);
                    fputs($connect, "Content-Length: " . strlen($soapRequest) . $newLine . $newLine);
                    fputs($connect, $soapRequest . $newLine);
                    $buffer = "";
                    while ($response = fgets($connect, 1024)) {
                        $buffer = $buffer . $response;
                    }
                    dd($buffer);
                    $buffer = self::parseData($buffer, "<GetAttLogResponse>", "</GetAttLogResponse>");
                    $buffer = explode("\r\n", $buffer);
                    $datas = [];
                    for ($i = 0; $i < count($buffer); $i++) {
                        $resource = self::parseData($buffer[$i], "<Row>", "</Row>");
                        if ($resource != "") {
                            $data = [];
                            $data['pin'] = self::parseData($resource, "<PIN>", "</PIN>");
                            $data['datetime'] = self::parseData($resource, "<DateTime>", "</DateTime>");
                            $data['verified'] = self::parseData($resource, "<Password>", "</Password>");
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

    public function isOnlineDevice($timeout = 1)
    {
        $handler = curl_init($this->ipAddress);
        curl_setopt_array($handler, [ CURLOPT_TIMEOUT => $timeout, CURLOPT_RETURNTRANSFER => true ]);
        $response = curl_exec($handler);
        curl_close($handler);

        return (boolean)$response;
    }
    
    /**
     * parse data funtion
     */
    private function parseData($data, $p1, $p2)
    {
        $data = " " . $data;
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
