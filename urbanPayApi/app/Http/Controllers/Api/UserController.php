<?php

namespace App\Http\Controllers\Api;


use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
// use Illuminate\Validation\Rules\Exists;
use Illuminate\Support\Facades\Session;
// use Illuminate\Support\Facades\Cache;
// use Illuminate\Support\Facades\Redis; // Import the Redis facade


class UserController extends Controller
{
    /**
     * Create User
     * @param Request $request
     * @return User
     */
    public function createUser(Request $request)
    {
        try {
            //Validated
            $validateUser = Validator::make(
                $request->all(),
                [
                    'name' => 'nullable',
                    'email' => 'nullable|email|unique:users,email',
                    'username' => 'nullable',
                    'phoneno' => 'nullable',
                    'pin' => 'nullable',
                    'password' => 'nullable'
                ]
            );

            if (strlen($request->pin) == 5) {
                if ($validateUser->fails()) {
                    return response()->json([
                        'status' => false,
                        'message' => 'validation error',
                        'errors' => $validateUser->errors()
                    ], 401);
                }

                $user = User::create([
                    'name' => $request->name,
                    'email' => $request->email,
                    'username' => $request->username,
                    'phoneno' => $request->phoneno,
                    'password' => Hash::make($request->password),
                    'pin' => Hash::make($request->pin)
                ]);
                Session::set('email', $request->email);
                // Cache::put('email', $request->email);


                return response()->json([
                    'status' => true,
                    'message' => 'User Created Successfully',
                    'token' => $user->createToken("API TOKEN")->plainTextToken
                ], 200);
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
     * @return User
     */
    public function loginUser(Request $request)
    {
        try {
            $validateUser = Validator::make(
                $request->all(),
                [
                    'email' => 'required|email',
                    'password' => 'required'
                ]
            );

            if ($validateUser->fails()) {
                return response()->json([
                    'status' => false,
                    'message' => 'validation error',
                    'errors' => $validateUser->errors()
                ], 401);
            }

            if (!Auth::attempt($request->only(['email', 'password']))) {
                return response()->json([
                    'status' => false,
                    'message' => 'Email & Password does not match with our record.',
                ], 401);
            }

            $user = User::where('email', $request->email)->first();

            $email = Session::put('email', $request->email);
            return response()->json(['message' => $email], 200);


            // return response()->json([
            //     'status' => true,
            //     'message' => 'User Logged In Successfully',
            //     'token' => $user->createToken("API TOKEN")->plainTextToken
            // ], 200);
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
            $email = Session::get('email');
            // return response()->json(['message' => $email], 200);

            $user =  User::where('email', $email)->exists();
            // if (Session::get('email')) {
                # code...
                $request->validate([
                    'pin' => 'required'
                ], [
                    'pin' => 'pin is required',
                ]);

                if (strlen($request->pin) == 5) {
                    # code...
                    if ($user) {
                        # code...
                        if ($request->pin == $user->pin) {
                            // session()->forget('key');
                            // User and pin are valid
                            return response()->json(['message' => 'Email and pin are valid.'], 200);
                            # code...
                        } else {
                            // User or pin is invalid
                            return response()->json(['message' => 'Invalid email or pin.'], 401);
                        }
                    } else {
                        return response()->json(['message' => 'invalid email'], 401);
                    }
                } else {
                    return response()->json([
                        'status' => 401,
                        'message' => 'pin must be 5 digits'
                    ]);
                }
            // } else {
            //     # code...
            //     return response()->json([
            //         'status' => 401,
            //         'message' => 'email is required'
            //     ], 500);
            // }
        } catch (\Throwable $e) {
            # code...
            return response()->json([
                'status' => false,
                'message' => $e->getMessage()
            ], 500);
        }
        # code...
    }
}
