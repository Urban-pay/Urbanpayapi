<?php

namespace App\Http\Controllers\Api;


use App\Models\user;
use App\Models\deleteduser;
use App\Models\otp;
use App\Models\wallet;
use App\Models\transaction;
use App\Models\beneficiary;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\DB;
use App\Mail\OtpVerificationMail;
use App\Mail\pinVerification;
use Laravel\Sanctum\HasApiTokens;
use Illuminate\Support\Facades\Http;
use GuzzleHttp\Client;
// use JWTAuth;
use Tymon\JWTAuth\Facades\JWTAuth;

// use DB;
// jwt-auth secret [bvuvNuoICaIMhK24iN4K9Th9ASkI965MHLG845SO5kJ52wMh0bIARiXsrRt6Hnqt] set successfully.



class UserController extends Controller
{
    /**
     * Create User
     * @param Request $request
     * @return user
     */

    public function createUser(Request $request)
    {
        try {
            $validatedData = $request->validate([
                'name' => 'nullable|string|max:255',
                'email' => 'nullable|string|email|max:255|unique:users',
                'username' => 'nullable|string|max:255',
                'phoneno' => 'nullable|max:255',
                'password' => 'nullable',
                'pin' => 'nullable|string',
            ]);

            if (strlen($request->pin) == 5) {
                $user = User::create([
                    'name' => $validatedData['name'],
                    'email' => $validatedData['email'],
                    'username' => $validatedData['username'],
                    'phoneno' => $validatedData['phoneno'],
                    'password' => Hash::make($validatedData['password']),
                    'pin' => Hash::make($validatedData['pin']),
                ]);


                // save to session
                $request->session()->put('email', $user->email);
                $request->session()->put('name', $user->name);
                $request->session()->put('username', $user->username);

                // generate token
                // $token = JWTAuth::fromUser($user);

                $token = $user->createToken('AuthToken')->plainTextToken;



                // email otp
                $user = User::where('email', $user->email)->first();


                if (!$user) {
                    return response()->json(['message' => 'User not found'], 404);
                }

                // Generate random OTP
                $otp = mt_rand(100000, 999999);

                // Store OTP in the database with the user's email
                $user->otp = $otp;
                $user->save();

                // Send email to user containing the OTP
                Mail::to($user->email)->send(new OtpVerificationMail($user->otp));




                try {

                    // create customers
                    // spliting fullname
                    $string = $user->name;
                    $words = explode(' ', $string); // Split the string into an array of words
                    $firstname = $words[0]; // First word
                    $lastname = $words[1]; // Second word

                    $response = Http::withHeaders([
                        'accept' => 'application/json',
                        'content-type' => 'application/json',
                        'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
                    ])->post('https://api.sandbox.getanchor.co/api/v1/customers', [
                        'data' => [
                            'type' => 'IndividualCustomer',
                            'attributes' => [
                                'fullName' => [
                                    'firstName' => $firstname,
                                    'lastName' => $lastname,
                                    'middleName' => '',
                                ],
                                'email' => $user->email,
                                'phoneNumber' => $user->phoneno,
                                'address' => [
                                    'addressLine_1' => '36 Araromi Street',
                                    'addressLine_2' => 'Onike',
                                    'country' => 'NG',
                                    'city' => 'Yaba',
                                    'postalCode' => 'NA',
                                    'state' => 'Lagos',
                                ],
                                'isSoleProprietor' => true,
                                'description' => 'string',
                                'doingBusinessAs' => ' ' . $firstname .' ' . $lastname .' INC',
                                'identificationLevel2' => [
                                    'gender' => 'Male',
                                    'dateOfBirth' => '1994-06-25',
                                    'selfieImage' => null,
                                    'bvn' => '22262222226',
                                ],
                                'identificationLevel3' => [
                                    'idType' => 'DRIVERS_LICENSE',
                                    'idNumber' => 'DL123456789',
                                    'expiryDate' => '2023-06-25',
                                ],
                            ],
                        ],
                    ]);
                    

                    $responseData = $response->json(); // Return JSON response from the API
                    // $data = json_decode($responseData, true);


                    // create deposit account
                    $response1 = Http::withHeaders([
                        'accept' => 'application/json',
                        'content-type' => 'application/json',
                        'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
                    ])->post('https://api.sandbox.getanchor.co/api/v1/accounts', [
                        'data' => [
                            'type' => 'DepositAccount',
                            'attributes' => [
                                'productName' => 'SAVINGS'
                            ],
                            'relationships' => [
                                'customer' => [
                                    'data' => [
                                        'id' =>'',
                                        'type' => ''
                                    ]
                                ]
                            ]
                        ]
                    ]);

                    $responseData1 = $response1->json(); // Return JSON response from the API


                    //  fetch balance 
                    $response2 = Http::withHeaders([
                        'accept' => 'application/json',
                        'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
                    ])->get('https://api.sandbox.getanchor.co/api/v1/accounts/balance/' .'' . '');

                    $responseData2 = $response2->json(); // Return JSON response from the API




                    // save data to database
                    // $request->session()->put('balance', $ressArray['general_wallet']['balance']);
                    // $request->session()->put('bearer', 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8');



                    // $wallet = wallet::create([
                    //     'user_id' => $user->id,
                    //     'wallet_id' => rand(),
                    //     'transaction_id' => rand(),
                    //     'acct_id' => $responseData['data']['id'],
                    // 'account_name' => $responseData['fullName']['firstName'] .' '. $responseData['fullName']['lastName'],
                    //     'urbanPayTag' => $validatedData['username'],
                    //     'account_email' => $responseData['email'],
                    //     'account_number' => $responseData['accountNumber'],
                    //     'currency' => $responseData['currency'],
                    //     'bank_id' => $responseData2['provider']['id'],
                    //     'bank_name' => $responseData2['data']['bank']['slug'],
                    //     'balance' => '0.00',
                    //     'account_reference' => $responseData2['customer']['customer_code'],
                    //     'status' => $responseData2['active'],
                    // ]);
                    return response()->json([
                        'data' => $responseData,
                        'data1' => $responseData1,
                        'data2' => $responseData2
                    ]);

                } catch (\GuzzleHttp\Exception\RequestException $e) {
                    if ($e->hasResponse()) {
                        $response = $e->getResponse();
                        $statusCode = $response->getStatusCode();
                        $errorMessage = $response->getBody()->getContents();
                    } else {
                        // Handle other request exceptions
                        $statusCode = $e->getCode();
                        $errorMessage = $e->getMessage();
                    }

                    return response()->json([
                        'error' => $errorMessage,
                        'status' => $statusCode
                    ], $statusCode);
                }
            } else {
                return response()->json([
                    'status' => 401,
                    'message' => 'pin must be 5 digits'
                ], 500);
            }
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }

    /**
     * Login The User
     * @param Request $request
     * @return user
     */
    public function loginUser(Request $request)
    {
        try {

            $credentials = $request->validate([
                'email' => 'required|string|email',
                'password' => 'required|string',
            ]);

            if (Auth::attempt($credentials)) {
                $user = Auth::user();
                $request->session()->put('email', $user->email);
                $request->session()->put('name', $user->name);
                $request->session()->put('username', $user->username);

                // $token = $user->createToken('AuthToken')->plainTextToken;

                // saving wallet details to session
                $wallet = wallet::where('user_id', $user->id)->first();
                $request->session()->put('user_id', $wallet->user_id);
                $request->session()->put('wallet_id', $wallet->wallet_id);
                $request->session()->put('transaction_id', $wallet->transaction_id);


                $user = User::where('email', $user->email)->first();
                // $token = JWTAuth::fromUser($user);

                if (!$user) {
                    return response()->json(['message' => 'User not found'], 404);
                }

                // Generate random OTP
                $otp = mt_rand(100000, 999999);

                // Store OTP in the database with the user's email
                $user->otp = $otp;
                $user->save();

                // Send email to user containing the OTP
                Mail::to($user->email)->send(new OtpVerificationMail($user->otp));

                $client = new Client();

                $headers = [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json'
                ];
                // Data to be sent in the request body
                $body = [
                    'email' => "hello@useurbanpay.com",
                    'password' => "@Urbanpay247!",
                    // Add more key-value pairs as needed
                ];

                $reques = $client->request('POST', 'https://sagecloud.ng/api/v2/merchant/authorization', [
                    'headers' => $headers,
                    'json' => $body
                ]);
                $res = $reques->getBody()->getContents();
                $resArray = json_decode($res, true);
                $access_token = $resArray['data']['token']['access_token'];


                // api balance request
                $headers = [
                    'Content-Type' => 'application/json',
                    'Accept' => 'application/json',
                    'Authorization' => 'Bearer ' . $access_token . '',
                ];


                $request1 = $client->request('GET', 'https://sagecloud.ng/api/v2/wallet/balance', [
                    'headers' => $headers
                ]);
                $ress = $request1->getBody()->getContents();
                $ressArray = json_decode($ress, true);

                $request->session()->put('balance', $ressArray['general_wallet']['balance']);
                $request->session()->put('bearer', $resArray['data']['token']['access_token']);


                return response()->json([
                    // 'token' => $token,
                    'token' =>  $ressArray['general_wallet']['balance'],
                    'user' => $user,
                    'message' => 'OTP sent successfully',
                    'auth' => $res,
                    'getapi' => $ress
                ], 401);
            }
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }


    public function pin(Request $request)
    {
        try {

            $email = $request->session()->get('email');

            if ($email) {
                # code...
                $credentials = $request->validate([
                    'pin' => 'required|string',
                ]);

                $user = User::where('email', $email)->first();

                if (!$user || !password_verify($credentials['pin'], $user->pin)) {
                    return response()->json(['message' => 'Invalid email or PIN'], 401);
                }

                // User is authenticated, return success response
                return response()->json(['message' => 'Login successful', 'user' => $user]);
            } else {
                # code...
                return response()->json([
                    'message' => 'email required',
                ]);
            }
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'status' => false,
                'message' => $e->getMessage()
            ], 500);
        }
        # code...
    }


    public function verifyOtp(Request $request)
    {
        $email = $request->session()->get('email');

        $user = User::where('email', $email)->first();
        $request->validate([
            'otp' => 'required',
        ]);

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        if ($request->otp == $user->otp) {
            // OTP is valid
            // Perform necessary actions (e.g., mark email as verified)
            $user->email_verified_at = now();
            $user->save();
            return response()->json(['message' => 'OTP verified successfully']);
        } else {
            // OTP is invalid
            return response()->json(['message' => 'Invalid OTP'], 401);
        }
    }


    public function deleteUser(Request $request, $id)
    {

        try {
            // Retrieve the user from the current database
            $user = User::findOrFail($id);

            // Backup user data before deleting
            $userData = $user->toArray();

            // Delete the user from the current database
            $user->delete();
            // Upload the user data to another database
            //  DB::connection('urbanPayApi')->table('deletedusers')->insert($userData);
            //    $deleteduser = deleteduser::create([
            //         'name' => $user->name,
            //         'email' => $user->email,
            //         'username' => $user->username,
            //         'phoneno' => $user->phoneno,
            //         'password' => $user->password,
            //         'pin' => $user->pin
            //     ]);
            return response()->json(['message' => 'Deleted successfully']);
        } catch (\Exception $e) {
            // Handle upload failure

            return response()->json(['message' => 'Failed to upload user data'], 500);
        }
    }

    // show one
    public function singleUser($id)
    {
        $user = User::find($id);
        if ($user) {
            return response()->json([$user], 202);
        } else {
            return response()->json([
                'message' => "User not found"
            ], 404);
        }
    }


    public function updateUserProfile(Request $request)
    {
        $email = $request->session()->get('email');
        $request->validate([
            'name' => 'required',
            'email' => 'required',
            'username' => 'required',
            'phoneno' => 'required',
        ]);

        if (User::where('email', $email)->exists()) {
            // $user = User::find($email);
            // $user->name = is_null($request->name) ? $user->name :  $request->name;
            // $user->email = is_null($request->email) ? $user->email :  $request->email;
            // $user->username = is_null($request->username) ? $user->username :  $request->username;
            // $user->phoneno = is_null($request->phoneno) ? $user->phoneno :  $request->phoneno;
            // $user->save();

            User::where('email', $email)->update([
                'name' => $request->name,
                'email' => $request->email,
                'username' => $request->username,
                'phoneno' => $request->phoneno,
            ]);

            return response()->json([
                "message" => "Profile Updated"
            ], 200);
        } else {
            return response()->json([
                "message" => "User not found"
            ], 404);
        }
    }

    public function updateUserProfilePinVerify(Request $request)
    {
        $email = $request->session()->get('email');
        $request->validate([
            'pin' => 'required',
        ]);

        if (strlen($request->pin) == 5) {

            $user = User::where('email', $email)->first();
            $otp = new otp;

            if (!$user) {
                return response()->json(['message' => 'User not found'], 404);
            }

            // Generate random OTP
            $rand = mt_rand(0, 999999);

            // Store OTP in the database with the user's email
            $otp->email = $email;
            $otp->otp = $rand;
            $otp->save();

            // Send email to user containing the OTP
            Mail::to($user->email)->send(new pinVerification($rand));
            $request->session()->put('pin', $request->pin);
            $request->session()->put('otp', $rand);
            return response()->json(['message' => 'otp sent succcessfully'], 404);
        } else {
            return response()->json([
                'status' => 401,
                'message' => 'pin must be 5 digits'
            ], 500);
        }
    }


    public function updateUserProfilePasswordVerify(Request $request)
    {
        $email = $request->session()->get('email');

        $request->validate([
            'password' => 'required',
        ]);


        $user = User::where('email', $email)->first();
        $otp = new otp;

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        // Generate random OTP
        $rand = mt_rand(100000, 999999);

        // Store OTP in the database with the user's email
        $otp->email = $email;
        $otp->otp = $rand;
        $otp->save();

        // Send email to user containing the OTP
        Mail::to($user->email)->send(new pinVerification($rand));
        $request->session()->put('password', $request->password);
        $request->session()->put('otp', $rand);
        return response()->json(['message' => 'otp sent succcessfully'], 404);
    }


    public function updateUserProfilePin(Request $request)
    {
        $email = $request->session()->get('email');
        $pin = $request->session()->get('pin');

        $otp = otp::where('otp', $request->otp)->first();
        $request->validate([
            'otp' => 'required',
        ]);

        // if (!$otp) {
        //     return response()->json(['message' => 'User not found'], 404);
        // }

        if ($otp) {
            // OTP is valid
            // Perform necessary actions (e.g., mark email as verified)
            $otp->verify = 'yes';
            $otp->save();
            if (User::where('email', $email)->exists()) {
                User::where('email', $email)->update([
                    'pin' => Hash::make($pin),
                ]);
                // $user = User::find($email);
                // $user->pin = Hash::make($pin);
                // $user->save();
                return response()->json([
                    "message" => "Pin Updated"
                ], 200);
            } else {
                return response()->json([
                    "message" => "User not found"
                ], 404);
            }
        } else {
            // OTP is invalid
            return response()->json(['message' => 'Invalid OTP'], 401);
        }
    }


    public function updateUserProfilePassword(Request $request)
    {

        $email = $request->session()->get('email');
        $password = $request->session()->get('password');

        $otp = otp::where('otp',  $request->otp)->first();
        $request->validate([
            'otp' => 'required',
        ]);

        // if (!$otp) {
        //     return response()->json(['message' => 'User not found'], 404);
        // }

        if ($otp) {
            // OTP is valid
            // Perform necessary actions (e.g., mark email as verified)
            $otp->verify = 'yes';
            $otp->save();
            if (User::where('email', $email)->exists()) {
                User::where('email', $email)->update([
                    'password' => Hash::make($password),
                ]);
                // $user = User::find($email);
                // $user->password = is_null($password) ? $user->password :  Hash::make($password);
                // $user->save();
                return response()->json([
                    "message" => "Password Updated"
                ], 200);
            } else {
                return response()->json([
                    "message" => "User not found"
                ], 404);
            }
        } else {
            // OTP is invalid
            return response()->json(['message' => 'Invalid OTP'], 401);
        }
    }

    public function getbankList(Request $request)
    {

        try {

            // get list of bank
            $client = new Client();
            $access_token = $request->session()->get('bearer');

            $headers1 = [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer ' . $access_token . ''
            ];
            $request1 = $client->request('GET', 'https://sagecloud.ng/api/v2/transfer/get-transfer-data', [
                'headers' => $headers1
            ]);
            $ress1 = $request1->getBody()->getContents();
            $ressArray1 = json_decode($ress1, true);

            return response()->json([
                'msg' => $ress1
            ]);
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }
    public function sendMoney(Request $request)
    {

        try {

            $request->validate([
                'reference' => 'nullable|string',
                'bank_code' => 'required|string',
                'bank_name' => 'required|string',
                'account_number' => 'required|string',
                'account_name' => 'required|string',
                'amount' => 'required|string',
                'narration' => 'required|string',
            ]);
            try {


                // verify bank account
                $client = new Client();
                $access_token = $request->session()->get('bearer');

                $headers = [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json',
                    'Authorization' => 'Bearer ' . $access_token . '',
                ];
                $body = '{
                  "bank_code": "' . $request->bank_code . '",
                  "account_number": ""' . $request->account_number . '"
                }';
                $request1 = $client->request('POST', 'https://sagecloud.ng/api/v2/transfer/verify-bank-account', [
                    'headers' =>  $headers,
                    'json' => $body
                ]);
                $ress = $request1->getBody()->getContents();
                $ressArray = json_decode($ress, true);


                // send  money
                $headers = [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json',
                    'Authorization' => 'Bearer ' . $access_token . ''
                ];
                // $body = '{
                //     "reference": "6A3EKXI5M6U7DAVL_tf1",
                //     "bank_code": "'.$request->bank_code.'",
                //     "account_number": "'.$request->account_number.'",
                //     "account_name": "'.$request->account_name.'",
                //     "amount": "'.$request->amount.'",
                //     "narration": "'.$request->narration.'"
                // }';
                $body = '{
                    "reference": "6A3EKXI5M6U7DAVL_tf1",
                    "bank_code": "044",
                    "account_number": "0058381844",
                    "account_name": "Samson Okemakinde",
                    "amount": "100",
                    "narration": "Test Transfer"
                }';
                $request2 = $client->request('POST', 'https://sagecloud.ng/api/v2/transfer/fund-transfer', [
                    'headers' => $headers,
                    'json' => $body
                ]);
                $response = $request2->getBody()->getContents();




                $transaction = transaction::create([
                    'user_id' => $request->session()->get('user_id'),
                    'wallet_id' => $request->session()->get('wallet_id'),
                    'transaction_id' => $request->session()->get('transaction_id'),
                    'reference' => $request->reference,
                    'bank_code' => $request->bank_code,
                    'bank_name' => $request->bank_name,
                    'account_number' => $request->account_number,
                    'account_name' => $request->account_name,
                    'amount' => $request->amount,
                    'urbanPayTag' => $request->urbanPayTag,
                    'narration' => $request->narration,
                    'status' => 'success',
                ]);

                $beneficiary = beneficiary::create([
                    'user_id' => $request->session()->get('user_id'),
                    'wallet_id' => $request->session()->get('wallet_id'),
                    'transaction_id' => $request->session()->get('transaction_id'),
                    'reference' => $request->reference,
                    'bank_code' => $request->bank_code,
                    'bank_name' => $request->bank_name,
                    'account_number' => $request->account_number,
                    'account_name' => $request->account_name,
                    'urbanPayTag' => $request->urbanPayTag,
                ]);
                return response()->json([
                    'message' => $ress,
                    'msg' => $response,
                ], 500);
            } catch (\Throwable $e) {
                return response()->json([
                    'status' => false,
                    'message' => $e->getMessage()
                ], 500);
            }
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }
    public function sendMoneyWithTag(Request $request)
    {

        try {

            $request->validate([
                // 'reference' => 'required|string',
                'bank_code' => 'required|string',
                'amount' => 'required|string',
                'urbanPayTag' => 'nullable|string',
                'narration' => 'required|string',
            ]);
            try {

                // get acount details
                $wallets = DB::table('wallets')
                    ->where('urbanPayTag', '=', $request->urbanPayTag)
                    ->get();


                // verify bank account
                $client = new Client();
                $access_token = $request->session()->get('bearer');

                $headers = [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json',
                    'Authorization' => 'Bearer ' . $access_token . '',
                ];
                $body = '{
                  "bank_code": "' . $request->bank_code . '",
                  "account_number": ""' . $wallets['account_number'] . '"
                }';
                $request1 = $client->request('POST', 'https://sagecloud.ng/api/v2/transfer/verify-bank-account', [
                    'headers' =>  $headers,
                    'json' => $body
                ]);
                $ress = $request1->getBody()->getContents();
                $ressArray = json_decode($ress, true);


                // send  money
                $headers = [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json',
                    'Authorization' => 'Bearer ' . $access_token . ''
                ];
                $body = '{
                    "reference": "' . $wallets['reference'] . '",
                    "bank_code": "' . $request->bank_code . '",
                    "account_number": "' . $wallets['account_number'] . '",
                    "account_name": "' . $wallets['account_name'] . '",
                    "amount": "' . $request->amount . '",
                    "narration": "' . $request->narration . '"
                }';
                // $body = '{
                //     "reference": "6A3EKXI5M6U7DAVL_tf1",
                //     "bank_code": "044",
                //     "account_number": "0058381844",
                //     "account_name": "Samson Okemakinde",
                //     "amount": "100",
                //     "narration": "Test Transfer"
                // }';
                $request2 = $client->request('POST', 'https://sagecloud.ng/api/v2/transfer/fund-transfer', [
                    'headers' => $headers,
                    'json' => $body
                ]);
                $response = $request2->getBody()->getContents();




                $transaction = transaction::create([
                    'user_id' => $request->session()->get('user_id'),
                    'wallet_id' => $request->session()->get('wallet_id'),
                    'transaction_id' => $request->session()->get('transaction_id'),
                    'reference' => $wallets['reference'],
                    'bank_code' => $request->bank_code,
                    'bank_name' => $wallets['bank_name'],
                    'account_number' => $wallets['account_number'],
                    'account_name' => $wallets['account_name'],
                    'amount' => $request->amount,
                    'urbanPayTag' => $request->urbanPayTag,
                    'narration' => $request->narration,
                    'status' => 'success',
                ]);

                $beneficiary = beneficiary::create([
                    'user_id' => $request->session()->get('user_id'),
                    'wallet_id' => $request->session()->get('wallet_id'),
                    'transaction_id' => $request->session()->get('transaction_id'),
                    'reference' => $wallets['reference'],
                    'bank_code' => $request->bank_code,
                    'bank_name' => $wallets['bank_name'],
                    'account_number' => $wallets['account_number'],
                    'account_name' => $wallets['account_name'],
                    'urbanPayTag' => $request->urbanPayTag,
                ]);
                return response()->json([
                    'message' => $ress,
                    'msg' => $response,
                    'wallets' => $wallets,
                ], 500);
            } catch (\Throwable $e) {
                return response()->json([
                    'status' => false,
                    'message' => $e->getMessage()
                ], 500);
            }
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }
    public function addMoney(Request $request)
    {
        try {
            # code...
            $user_id = $request->session()->get('user_id');
            $wallet_id = $request->session()->get('wallet_id');
            // $wallets = wallet::where('user_id', $user_id)->first();
            $wallets = DB::table('wallets')
                ->where('user_id', '=', $user_id)
                ->where('wallet_id', '=', $wallet_id)
                ->get();

            return response()->json([
                'data' => $wallets
            ], 200);
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
    public function transactionGet(Request $request)
    {
        try {
            # code...
            $user_id = $request->session()->get('user_id');
            $wallet_id = $request->session()->get('wallet_id');
            // $wallets = wallet::where('user_id', $user_id)->first();
            $transactions = DB::table('transactions')
                ->where('user_id', '=', $user_id)
                ->where('wallet_id', '=', $wallet_id)
                ->get();

            return response()->json([
                'data' => $transactions
            ], 200);
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
}
