<?php

namespace App\Http\Controllers\Api;


use App\Models\user;
use App\Models\deleteduser;
use App\Models\otp;
use App\Models\wallet;
use App\Models\transaction;
use App\Models\beneficiary;
use App\Models\notifications;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\DB;
use App\Mail\OtpVerificationMail;
use App\Mail\pinVerification;
use App\Mail\notificationMail;
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
        // try {
        $validatedData = $request->validate([
            'name' => 'nullable|string|max:255',
            'email' => 'nullable|string|email|max:255|unique:users',
            'username' => 'nullable|string|max:255',
            'phoneno' => 'nullable|max:255',
            'password' => 'nullable',
            'pin' => 'nullable|string',
            'firstName' => 'required',
            'lastName'   => 'required',
            'middleName' => 'nullable',
            'phoneNumber' => 'required',
            'addressLine_1'   => 'required',
            'addressLine_2' => 'nullable',
            'country' => 'required',
            'city' => 'required',
            'postalCode' => 'required',
            'state' => 'required',
            // 'isSoleProprietor' => 'required',
            'description' => 'nullable',
            'doingBusinessAs' => 'required',
            'gender' => 'required',
            'dateOfBirth'   => 'required',
            'selfieImage' => 'required',
            'bvn' => 'required',
            'idType' => 'required',
            'idNumber' => 'required',
            'expiryDate' => 'required'
        ]);

        if (strlen($request->pin) == 5) {
            $string = $validatedData['name'];
            $words = explode(' ', $string); // Split the string into an array of words
            $firstname = $words[0]; // First word
            $lastname = $words[1]; // Second word

            // Generate random OTP
            $otp = mt_rand(100000, 999999);

            $user = User::create([
                'user_id' => mt_rand(1, 9999999),
                'name' => $validatedData['name'],
                'email' => $validatedData['email'],
                'username' => $validatedData['username'],
                'phoneno' => $validatedData['phoneno'],
                'password' => Hash::make($validatedData['password']),
                'pin' => Hash::make($validatedData['pin']),
                'otp' => $otp,
                'firstName' => $firstname,
                'lastName'   => $lastname,
                'middleName' => $validatedData['middleName'],
                'phoneNumber' => $validatedData['phoneNumber'],
                'addressLine_1'   => $validatedData['addressLine_1'],
                'addressLine_2' => $validatedData['addressLine_2'],
                'country' => $validatedData['country'],
                'city' => $validatedData['city'],
                'postalCode' => $validatedData['postalCode'],
                'state' => $validatedData['state'],
                'isSoleProprietor' => true,
                // 'isSoleProprietor' => $validatedData['isSoleProprietor'],
                'description' => $validatedData['description'],
                'doingBusinessAs' => $validatedData['doingBusinessAs'],
                'gender' => $validatedData['gender'],
                'dateOfBirth'   => $validatedData['dateOfBirth'],
                'selfieImage' => $validatedData['selfieImage'],
                'bvn' => $validatedData['bvn'],
                'idType' => $validatedData['idType'],
                'idNumber' => $validatedData['idNumber'],
                'expiryDate' => $validatedData['expiryDate'],
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

            // Store OTP in the database with the user's email
            // $user->otp = $otp;
            $user->save();
            // $user->delete();

            // Send email to user containing the OTP
            Mail::to($user->email)->send(new OtpVerificationMail($user->otp));

            try {

                // create customers
                // 'data' => [
                //     'type' => 'IndividualCustomer',
                //     'attributes' => [
                //         'fullName' => [
                //             'firstName' => $firstname,
                //             'lastName' => $lastname,
                //             'middleName' => $user->middleName,
                //         ],
                //         'email' => $user->email,
                //         'phoneNumber' => $user->phoneno,
                //         'address' => [
                //             'addressLine_1' => $user->addressLine_1,
                //             'addressLine_2' => $user->addressLine_2,
                //             'country' => $user->country,
                //             'city' => $user->city,
                //             'postalCode' => $user->postalCode,
                //             'state' => $user->state,
                //         ],
                //         'isSoleProprietor' => $user->isSoleProprietor,
                //         'description' => $user->description,
                //         'doingBusinessAs' => "{$firstname} {$lastname} INC",
                //         'identificationLevel2' => [
                //             'gender' => $user->gender,
                //             'dateOfBirth' => $user->dateOfBirth,
                //             'selfieImage' => $user->selfieImage,
                //             'bvn' => $user->bvn,
                //         ],
                //         'identificationLevel3' => [
                //             'idType' => $user->idType,
                //             'idNumber' => $user->idNumber,
                //             'expiryDate' => $user->expiryDate,
                //         ],
                //     ],
                // ],
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
                                'firstName' => 'Toluwanimi',
                                'lastName' => 'Adejumobi',
                                'middleName' => 'ephraim',
                            ],
                            'email' => 'adejumobitoluwanimi44@gmail.com',
                            'phoneNumber' => '09190484599',
                            'address' => [
                                'addressLine_1' => '36 Araromi Street',
                                'addressLine_2' => 'Onike',
                                'country' => 'NG',
                                'city' => 'Lagos',
                                'postalCode' => 'NA',
                                'state' => 'Lagos',
                            ],
                            'isSoleProprietor' => true,
                            'description' => 'string',
                            'doingBusinessAs' => 'Toluwanimi Adejumobi INC',
                            'identificationLevel2' => [
                                'gender' => 'Male',
                                'dateOfBirth' => '1994-06-25',
                                'selfieImage' => 'bxxvxvxbvasbbxvxvx=',
                                'bvn' => '76454985720',
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

                // verify kyc
                $url = "https://api.sandbox.getanchor.co/api/v1/customers/" . $responseData['data']['id'] . "/verification/individual";
                $body = [
                    "data" => [
                        "type" => "Verification",
                        "attributes" => [
                            "level" => "TIER_2",
                            "level2" => [
                                "bvn" => "76454985720",
                                "selfie" => "bxxvxvxbvasbbxvxvx=",
                                "dateOfBirth" => "1994-06-25",
                                "gender" => "Male"
                            ],
                            "level3" => [
                                "idNumber" => "DL123456789",
                                "idType" => "DRIVERS_LICENSE",
                                "expiryDate" => "2023-06-25"
                            ]
                        ]
                    ]
                ];
                $headers = [
                    'accept' => 'application/json',
                    'content-type' => 'application/json',
                    'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
                ];
                $response3 = Http::withHeaders($headers)->post($url, $body);
                $responseData3 = $response3->json();



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
                                    'id' => $responseData['data']['id'],
                                    'type' => $responseData['data']['type']
                                ]
                            ]
                        ]
                    ]
                ]);
                $responseData1 = $response1->json(); // Return JSON response from the API



                // fetch deposit account
                $url = 'https://api.sandbox.getanchor.co/api/v1/accounts/' . $responseData1['data']['id'] . '?include=DepositAccount';
                $response4 = Http::withHeaders([
                    'accept' => 'application/json',
                    'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
                ])->get($url);
                $responseData4 = $response4->json(); // Return JSON response from the API

                // get virtualnuban
                $url = "https://api.sandbox.getanchor.co/api/v1/virtual-nubans/" . $responseData4['data']['relationships']['virtualNubans']['data'][0]['id'] . "";
                $response5 = Http::withHeaders([
                    'accept' => 'application/json',
                    'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
                ])->get($url);
                $responseData5 = $response5->json(); // Return JSON response from the API


                // save data to database
                $request->session()->put('balance', 0);
                $request->session()->put('user_id', $responseData['data']['id']);
                $request->session()->put('wallet_id', $responseData1['data']['id']);
                $request->session()->put('virtual_id', $responseData5['data']['id']);
                $request->session()->put('bearer', 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8');

                $wallet = wallet::create([
                    'user_id' => $responseData['data']['id'],
                    'wallet_id' => $responseData1['data']['id'],
                    'transaction_id' => rand(),
                    'acct_id' => $responseData5['data']['id'],
                    'account_name' => $responseData5['data']['attributes']['accountName'],
                    'urbanPayTag' => $validatedData['username'],
                    'account_email' => $responseData['data']['attributes']['email'],
                    'account_number' => $responseData5['data']['attributes']['accountNumber'],
                    'currency' => $responseData5['data']['attributes']['currency'],
                    'bank_id' => $responseData5['data']['attributes']['bank']['id'],
                    'bank_name' => $responseData5['data']['attributes']['bank']['name'],
                    'bank_code' => $responseData5['data']['attributes']['bank']['nipCode'],
                    'balance' => 0.0,
                    'account_reference' => 'null',
                    'status' => $responseData5['data']['attributes']['status'],
                ]);

                $notification = notifications::create([
                    'user_id' => $request->session()->get('email'),
                    'title' => 'Account Creation',
                    'message' => 'Your Account has been created succesfully.'
                ]);
                // Send notfication email to user containing the OTP
                Mail::to($user->email)->send(new notificationMail('Account Creation', 'Your Account has been created succesfully.'));

                return response()->json([
                    'data' => $responseData,
                    'data1' => $responseData1,
                    'data3' => $responseData3,
                    'data4' => $responseData4,
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
        // } catch (\Throwable $th) {
        //     return response()->json([
        //         'status' => false,
        //         'message' => $th->getMessage()
        //     ], 500);
        // }
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
            $user = User::where('email', $request->email)->first();

            if ($user) {
                // $user = Auth::user();
                $request->session()->put('email', $user->email);
                $request->session()->put('name', $user->name);
                $request->session()->put('username', $user->username);

                // $token = $user->createToken('AuthToken')->plainTextToken;

                // saving wallet details to session
                $wallet = wallet::where('user_id', $user->id)->first();
                $request->session()->put('balance', $wallet->balance);
                $request->session()->put('user_id', $wallet->user_id);
                $request->session()->put('wallet_id', $wallet->wallet_id);
                $request->session()->put('virtual_id', $wallet->acct_id);
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


                // inserting notifcation
                $title = "Welcome back, {$user->firstName} {$user->lastName}";
                $msg = 'You have successfully logged in.';
                $notification = notifications::create([
                    'user_id' => $request->session()->get('user_id'),
                    'title' => $title,
                    'message' => $msg
                ]);
                // Send notfication email to user containing the OTP
                Mail::to($user->email)->send(new notificationMail($title, $msg));

                return response()->json([
                    'token' => $otp,
                    'user' => $user,
                    'message' => 'OTP sent successfully',
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
                // inserting notifcation
                $title = "Welcome back, {$user->firstName} {$user->lastName}";
                $msg = 'You have successfully logged in.';
                $notification = notifications::create([
                    'user_id' => $request->session()->get('user_id'),
                    'title' => $title,
                    'message' => $msg
                ]);
                // Send notfication email to user containing the OTP
                Mail::to($user->email)->send(new notificationMail($title, $msg));

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
            // Delete the user from the anchor database
            $response = Http::withHeaders([
                'accept' => 'application/json',
                'content-type' => 'application/json',
                'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8'
            ])->get('https://api.sandbox.getanchor.co/api/v1/customers/' . $request->session()->get('user_id') . '');
            $responseData = $response->json();
            // inserting notifcation
            $title = "User Deleted";
            $msg = 'The user has been successfully deleted.';
            $notification = notifications::create([
                'user_id' => $request->session()->get('user_id'),
                'title' => $title,
                'message' => $msg
            ]);
            // Send notfication email to user containing the OTP
            Mail::to($user->email)->send(new notificationMail($title, $msg));

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
            return response()->json(['message' => 'Deleted successfully', 'data' => $responseData]);
        } catch (\Exception $e) {
            // Handle upload failure

            return response()->json(['message' => 'Failed to upload user data'], 500);
        }
    }

    // show one
    public function listUser()
    {
        $url = 'https://api.sandbox.getanchor.co/api/v1/customers';

        $response = Http::withHeaders([
            'accept' => 'application/json',
            'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
        ])->get($url);

        $responseData =  $response->json(); // Return the JSON response from the API
        $url = 'https://api.sandbox.getanchor.co/api/v1/virtual-nubans';

        $response1 = Http::withHeaders([
            'accept' => 'application/json',
            'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
        ])->get($url);

        $responseData1 =  $response1->json(); // Return the JSON response from the API
        return response()->json([
            'data' => $responseData,
            'data1' => $responseData1
        ]);
    }


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

            // inserting notifcation
            $title = "Profile Updated Successfully!";
            $msg = 'Profile Updated Successfully!';
            $notification = notifications::create([
                'user_id' => $request->session()->get('user_id'),
                'title' => $title,
                'message' => $msg
            ]);
            // Send notfication email to user containing the OTP
            Mail::to($request->session()->get('email'))->send(new notificationMail($title, $msg));


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
            // inserting notifcation
            $title = "Profile Updated Successfully!";
            $msg = 'Profile Updated Successfully!';
            $notification = notifications::create([
                'user_id' => $request->session()->get('user_id'),
                'title' => $title,
                'message' => $msg
            ]);
            // Send notfication email to user containing the OTP
            Mail::to($request->session()->get('email'))->send(new notificationMail($title, $msg));
            // inserting notifcation
            $title = "Pin Updated Successfully!";
            $msg = 'Pin Updated Successfully!';
            $notification = notifications::create([
                'user_id' => $request->session()->get('user_id'),
                'title' => $title,
                'message' => $msg
            ]);
            // Send notfication email to user containing the OTP
            Mail::to($request->session()->get('email'))->send(new notificationMail($title, $msg));

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
            $url = 'https://api.sandbox.getanchor.co/api/v1/banks';

            $response = Http::withHeaders([
                'accept' => 'application/json',
                'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
            ])->get($url);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                'msg' => $responseData
            ]);
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }
    public function verifyBank(Request $request)
    {

        try {
            $validatedData = $request->validate([
                'bankIdOrBankCode' => 'required|string',
                'accountNumber' => 'required|string'

            ]);



            $url = 'https://api.sandbox.getanchor.co/api/v1/payments/verify-account/' . $validatedData['bankIdOrBankCode'] . '/' . $validatedData['accountNumber'];

            $response = Http::withHeaders([
                'accept' => 'application/json',
                'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
            ])->get($url);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                'msg' => $responseData
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

        // try {

        // try {

        // get accountid from session
        // $acct_id = '17164168624170-anc_acc';
        $acct_id = $request->session()->get('wallet_id');

        $wallet = wallet::where('wallet_id', $acct_id);


        $validatedData = $request->validate([
            'bankIdOrBankCode' => 'required|string',
            'accountNumber' => 'required|string',
            'reference' => 'required|string',
            'bank_name' => 'required|string',
            'account_name' => 'required|string',
            'amount' => 'required|string',
            'narration' => 'required|string',
        ]);


        // verify bank account
        $url = 'https://api.sandbox.getanchor.co/api/v1/payments/verify-account/' . $validatedData['bankIdOrBankCode'] . '/' . $validatedData['accountNumber'];

        $response = Http::withHeaders([
            'accept' => 'application/json',
            'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
        ])->get($url);

        $responseData = $response->json(); // Return the JSON response from the API

        // create counter party
        $url = 'https://api.sandbox.getanchor.co/api/v1/counterparties';

        $response1 = Http::withHeaders([
            'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
            'Content-Type' => 'application/json',
        ])->post($url, [
            'data' => [
                'type' => 'CounterParty',
                'attributes' => [
                    'accountName' =>  $responseData['data']['attributes']['accountName'], //'OLAMODE ADE SOBOKUNLE',
                    'accountNumber' => $responseData['data']['attributes']['accountNumber'], //'0068970263',
                    'bankCode' => $responseData['data']['attributes']['bank']['nipCode'], //'000007'
                ]
            ]
        ]);

        $responseData1 = $response1->json(); // Return the JSON response from the API

        // create transfer
        $url = 'https://api.sandbox.getanchor.co/api/v1/transfers';

        $response2 = Http::withHeaders([
            'Content-Type' => 'application/json',
            'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
        ])->post($url, [
            "data" => [
                "type" => "NIPTransfer",
                "attributes" => [
                    "amount" => $validatedData['amount'],
                    "currency" => "NGN",
                    "reason" => $validatedData['narration'], //"Olamide 3 again",
                    "reference" => $validatedData['reference'], //"232hfndnbi2r72rgf29ufgb"
                ],
                "relationships" => [
                    "account" => [
                        "data" => [
                            "id" => $acct_id, //"16517725619924-anc_acc",
                            "type" => "DepositAccount"
                        ]
                    ],
                    "counterParty" => [
                        "data" => [
                            "id" => $responseData1['data']['id'], //"16518495829780-anc_cp",
                            "type" => "CounterParty"
                        ]
                    ]
                ]
            ]
        ]);
        $responseData2 = $response2->json(); // Return the JSON response from the API

        // verify transfer
        $url = 'https://api.sandbox.getanchor.co/api/v1/transfers/verify/' . $responseData2['data']['id'];

        $response3 = Http::withHeaders([
            'accept' => 'application/json',
            'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
        ])->get($url);

        $responseData3 = $response3->json(); // Return the JSON response from the API

        // $urbanPayTag = 'sam';
        $wallet->urbanPayTag = 'urbanpay-tolu';

        $transaction = transaction::create([
            'user_id' => '17164158629698-anc_ind_cst',
            'wallet_id' => '17164168624170-anc_acc',
            'transaction_id' => mt_rand(0, 999999),
            // 'user_id' => $request->session()->get('user_id'),
            // 'wallet_id' => $request->session()->get('wallet_id'),
            // 'transaction_id' => $request->session()->get('transaction_id'),
            'reference' => $request->reference,
            'toBank_code' => $request->bankIdOrBankCode,
            'toBank_name' => $request->bank_name,
            'toAccount_number' => $request->accountNumber,
            'toAccount_name' => $request->account_name,
            'account_number' => $responseData['data']['attributes']['accountNumber'],
            'account_name' => $responseData['data']['attributes']['accountName'],
            'bank_code' => $responseData['data']['attributes']['bank']['nipCode'],
            'bank_name' => $responseData['data']['attributes']['bank']['name'],
            'amount' => $request->amount,
            'narration' => $request->narration,
            'status' => 'success',
        ]);
        // 4397016384
        // 17164181504227-anc_va

        $beneficiary = beneficiary::create([
            'user_id' => '17164158629698-anc_ind_cst',
            'wallet_id' => '17164168624170-anc_acc',
            'transaction_id' => mt_rand(0, 999999),
            // 'user_id' => $request->session()->get('user_id'),
            // 'wallet_id' => $request->session()->get('wallet_id'),
            // 'transaction_id' => $request->session()->get('transaction_id'),
            'reference' => $request->reference,
            // 'reference' => $uniqueId,
            'bank_code' => $request->bankIdOrBankCode,
            'bank_name' => $request->bank_name,
            'account_number' => $request->accountNumber,
            'account_name' => $request->account_name,
            'urbanPayTag' => $wallet->urbanPayTag,
            // 'urbanPayTag' => $urbanPayTag,
        ]);
        // fetching balance
        $url = 'https://api.sandbox.getanchor.co/api/v1/accounts/balance/' . $acct_id;

        $response4 = Http::withHeaders([
            'accept' => 'application/json',
        ])->get($url);

        $responseData4 = $response4->json(); // Return the JSON response from the API

        // inserting notifcation
        $title = "Transfer Successful";
        $msg = "Your payment of NGN {$request->amount} to " . $responseData1['data']['attributes']['accountName'] . " has been processed successfully. Your new balance is NGN " . $responseData4['data']['availableBalance'] . " ";
        $notification = notifications::create([
            'user_id' => $request->session()->get('user_id'),
            'title' => $title,
            'message' => $msg
        ]);

        // Send notfication email to user containing the OTP
        Mail::to($request->session()->get('email'))->send(new notificationMail($title, $msg));
        return response()->json([
            'data' => $responseData,
            'data1' => $responseData1,
            'data2' => $responseData2,
            'data3' => $responseData3
        ], 500);
        // } catch (\Throwable $e) {
        //     return response()->json([
        //         'status' => false,
        //         'message' => $e->getMessage()
        //     ], 500);
        // }
        // } catch (\Throwable $th) {
        //     return response()->json([
        //         'status' => false,
        //         'message' => $th->getMessage()
        //     ], 500);
        // }
    }

    public function sendMoneyWithTag(Request $request)
    {

        try {

            $request->validate([
                'reference' => 'required|string',
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
            // $user_id = $request->session()->get('user_id');
            $wallet_id = $request->session()->get('wallet_id');
            $wallets = wallet::where('wallet_id', $wallet_id)->first();
            // $wallets = DB::table('wallets')
            //     ->where('user_id', '=', $user_id)
            //     ->where('wallet_id', '=', $wallet_id)
            //     ->get();

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
    public function transactionGetALL(Request $request)
    {
        try {
            # code...
            // $user_id = $request->session()->get('user_id');
            // $wallet_id = $request->session()->get('wallet_id');
            // // $wallets = wallet::where('user_id', $user_id)->first();
            // $transactions = DB::table('transactions')
            //     ->where('user_id', '=', $user_id)
            //     ->where('wallet_id', '=', $wallet_id)
            //     ->get();

            $url = 'https://api.sandbox.getanchor.co/api/v1/transfers';

            $response = Http::withHeaders([
                'accept' => 'application/json',
                'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
            ])->get($url);

            // $url = 'https://api.sandbox.getanchor.co/api/v1/transactions';

            // $response = Http::withHeaders([
            //     'accept' => 'application/json',
            //     'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
            // ])->get($url);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                // 'data' => $transactions,
                'data1' => $responseData
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
            $validatedData = $request->validate([
                'transactionId' => 'required|string',
            ]);

            $url = 'https://api.sandbox.getanchor.co/api/v1/transfers/' . $validatedData['transactionId'];

            $response = Http::withHeaders([
                'accept' => 'application/json',
                'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
            ])->get($url);


            // $url = 'https://api.sandbox.getanchor.co/api/v1/transactions/' . $validatedData['transactionId'];

            // $response = Http::withHeaders([
            //     'accept' => 'application/json',
            //     'x-anchor-key' => 'y9k7N.79abd6fa47555b6c8b79f74ac55c7d9da5287687b2b2a1573f9c0869f06ec5ee55b892e3b9c64ecfe24912bdda1c0d993ca8',
            // ])->get($url);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                // 'data' => $transactions,
                'data1' => $responseData
            ], 200);
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
    public function logout(Request $request)
    {
        try {

            // Remove multiple items from the session
            $request->session()->forget(['email', 'name', 'username', 'user_id', 'balance', 'wallet_id', 'virtual_id', 'transaction_id']);


            return response()->json([
                "message" =>  "Successfully logged out"
            ], 200);
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
    public function UserdetailsByteBridge(Request $request)
    {
        try {
            $url = 'https://bytebridge.com.ng/api/user/';
            $token = 'e3822593c7c9f818b613cbd9d5bd078d3fdf7de4';
            $response = Http::withHeaders([
                'Authorization' => "Token {$token}",
                'Content-Type' => 'application/json',
            ])->get($url);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
    public function BuyData(Request $request)
    {
        try {
            $url = 'https://bytebridge.com.ng/api/data/';

            $headers = [
                'Authorization' => 'Token e3822593c7c9f818b613cbd9d5bd078d3fdf7de4',
                'Content-Type' => 'application/json',
            ];

            $request->validate([
                'network_id' => 'required|string',
                'mobile_number' => 'required|string',
                'plan_id' => 'required|string',
            ]);

            $body = [
                'network' => $request->input('network_id'),
                'mobile_number' => $request->input('mobile_number'),
                'plan' => $request->input('plan_id'),
                'Ported_number' => true,
            ];

            $response = Http::withHeaders($headers)->post($url, $body);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
    public function fetchDataTransaction()
    {
        try {
            $url = 'https://bytebridge.com.ng/api/data/';

            $response = Http::get($url);

            // return $response->json(); // Return the JSON response from the API
            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function fetchDataTransactionSingle(Request $request)
    {
        try {
            $request->validate([
                'id' => 'required|string',

            ]);
            $id = $request->id;
            $url = "https://bytebridge.com.ng/api/data/$id";

            $response = Http::get($url);

            // return $response->json(); // Return the JSON response from the API
            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function topUp(Request $request)
    {

        try {
            $request->validate([
                'network_id' => 'required|string',
                'mobile_number' => 'required|string',
                'plan_id' => 'required|string',
            ]);
            $url = 'https://bytebridge.com.ng/api/topup/';

            $headers = [
                'Authorization' => 'Token e3822593c7c9f818b613cbd9d5bd078d3fdf7de4',
                'Content-Type' => 'application/json'
            ];

            $body = [
                'network' => $request->input('network_id'),
                'amount' => $request->input('amount'),
                'mobile_number' => $request->input('phone'),
                'Ported_number' => true,
                'airtime_type' => 'VTU'
            ];

            $response = Http::withHeaders($headers)->post($url, $body);

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function FetchAirtimeTransactionSingle(Request $request)
    {
        try {
            $request->validate([
                'id' => 'required|string',

            ]);
            $id = $request->id;
            $url = "https://bytebridge.com.ng/api/data/{$id}";

            $response = Http::withHeaders([
                'Authorization' => 'Token e3822593c7c9f818b613cbd9d5bd078d3fdf7de4',
                'Content-Type' => 'application/json',
            ])->get($url);

            // return $response->json(); // Return the JSON response from the API
            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }

    }
     public function billPayment(Request $request)
    {
        try{
            $request->validate([
                'disco_name' => 'required|string',
                'amount' => 'required|string',
                'meter_number' => 'required|string',
                'MeterType' => 'required|string',

            ]);

            $headers = [
                'Authorization' => 'Token e3822593c7c9f818b613cbd9d5bd078d3fdf7de4',
                'Content-Type' => 'application/json'
            ];

            $body = json_encode([
                'disco_name' => $request->disco_name,
                'amount' => $request->amount,
                'meter_number' => $request->meter_number,
                'MeterType' => $request->MeterType // Replace with meter type id (PREPAID:1, POSTPAID:2)
            ]);

            $response = Http::withHeaders($headers)->post('https://bytebridge.com.ng/api/billpayment/', json_decode($body, true));

            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function getBillPayment(Request $request)
    {
        try {
            # code...
            $request->validate([
                'id' => 'required|string',

            ]);
            $id = $request->id;
            $url = "https://bytebridge.com.ng/api/billpayment/{$id}";
            $headers = [
                'Authorization' => 'Token e3822593c7c9f818b613cbd9d5bd078d3fdf7de4',
            ];
    
            $response = Http::withHeaders($headers)->get($url);
    
            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
    public function subscribeToCable(Request $request)
    {
        try {
            # code...
            $headers = [
                'Authorization' => 'Token e3822593c7c9f818b613cbd9d5bd078d3fdf7de4',
                'Content-Type' => 'application/json',
            ];
            $request->validate([
                'cablename' => 'required|string',
                'cableplan' => 'required|string',
                'smart_card_number' => 'required|string',


            ]);
    
            $body = json_encode([
                'cablename' => 'cablename id', // Replace with actual cablename id
                'cableplan' => 'cableplan id', // Replace with actual cableplan id
                'smart_card_number' => 'meter', // Replace with actual meter value
            ]);
    
            $response = Http::withHeaders($headers)
                            ->post('https://bytebridge.com.ng/api/cablesub/', json_decode($body, true));
    
            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function getCableSubscription(Request $request)
    {
  
        try {
            # code...
            $request->validate([
                'id' => 'required|string',
            ]);
            $id = $request->id;
            $url = "https://bytebridge.com.ng/api/cablesub/{$id}";
        
            $response = Http::withHeaders([
                'Authorization' => 'Token e3822593c7c9f818b613cbd9d5bd078d3fdf7de4',
                'Content-Type' => 'application/json',
            ])->get($url);
    
            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
    public function validateIUC(Request $request)
    {
        try {
            # code...
            $request->validate([
                'smart_card_number' => 'required|string',
                'cablename' => 'required|string',
            ]);
            $url = 'https://bytebridge.com.ng/ajax/validate_iuc';
            $headers = [
                'Authorization' => 'Token e3822593c7c9f818b613cbd9d5bd078d3fdf7de4',
                'Content-Type' => 'application/json',
            ];
    
            $queryParams = [
                'smart_card_number' => $request->input('smart_card_number'),
                'cablename' => $request->input('cablename'),
            ];
    
            $response = Http::withHeaders($headers)->get($url, $queryParams);
    
            $responseData = $response->json(); // Return the JSON response from the API

            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
     
    }

    public function validateMeter(Request $request)
    {
        try {
            # code...
            $request->validate([
                'meternumber' => 'required|string',
                'disconame' => 'required|string',
                'metertype' => 'required|string',
            ]);
            $url = 'https://bytebridge.com.ng/ajax/validate_meter_number';
            $headers = [
                'Authorization' => 'Token 66f2e5c39ac8640f13cd888f161385b12f7e5e92',
                'Content-Type' => 'application/json',
            ];
    
            $query = [
                'meternumber' => $request->input('meternumber'),
                'disconame' => $request->input('disconame'),
                'mtype' => $request->input('metertype'),
            ];
    
            $response = Http::withHeaders($headers)->get($url, $query);
    
            $responseData = $response->json(); // Return the JSON response from the API
    
            return response()->json([
                "data" =>  $responseData
            ], 200);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => $e->getMessage()
            ], 500);
        }
    }
}
