<?php

namespace App\Http\Controllers\Api;


use App\Models\user;
use App\Models\deleteduser;
use App\Models\otp;
use App\Models\wallet;
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

// use DB;




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




                $client = new Client();

                // Define your headers
                $headers = [
                    'Content-Type' => 'application/json',
                    'Authorization' => 'SCSec-L-9c0e1ac4b4fc4ee88b23276a091d7a02'
                ];
        
                // Data to be sent in the request body
                $data = [
                    'account_name' => $user->name,
                    'email' => $user->email
                    // Add more key-value pairs as needed
                ];
        
                try {
                    // Make the API request with headers and request body
                    $response = $client->request('POST', 'https://sagecloud.ng/api/v3/virtual-account/generate', [
                        'headers' => $headers,
                        'json' => $data
                    ]);
        
                    $statusCode = $response->getStatusCode();
                    $responseData = $response->getBody()->getContents();
                    $responseDataArray = json_decode($responseData,true);


                    $request = $client->request('GET', 'https://sagecloud.ng/api/v2/wallet/balance', $headers);
                    $res = $request->getBody()->getContents();
                    $resArray = json_decode($res,true);
                    
                    // $wallet = wallet::create([
                    //     'user_id' => $user->id,
                    //     'account_name' => $responseDataArray['data']['account_details']['account_name'],
                    //     'account_email' => $responseDataArray['data']['account_details']['account_email'],
                    //     'account_number' => $responseDataArray['data']['account_details']['account_number'],
                    //     'currency' => 'NGN',
                    //     'bank_name' => $responseDataArray['data']['account_details'] ['bank_name'],
                    //     // 'balance' => $resArray['general_wallet']['balance'],
                    //     'account_reference' => $responseDataArray['data']['account_details']['account_reference'],
                    //     // 'status' => $resArray['general_wallet']['status'],
                    // ]);
    
                    return response()->json([
                        'status' => $statusCode,
                        'data' => $responseData,
                        'data2' => $responseDataArray,
                        'res' => $resArray
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


            

                // return response()->json(['token' => $token, 'user' => $user, 'message' => 'OTP sent successfully']);


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
                $token = $user->createToken('AuthToken')->plainTextToken;

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



                // return response()->json(['token' => $token, 'user' => $user, 'message' => 'OTP sent successfully']);
            }
            // return response()->json(['message' => 'Unauthorized'], 401);
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
}
