<?php

namespace App\Http\Controllers\Api;


use App\Models\user;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Mail;
use App\Mail\OtpVerificationMail;





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
                'pin' => 'nullable|string'
            ]);

            if (strlen($request->pin) == 5) {
                $user = User::create([
                    'name' => $validatedData['name'],
                    'email' => $validatedData['email'],
                    'username' => $validatedData['username'],
                    'phoneno' => $validatedData['phoneno'],
                    'password' => Hash::make($validatedData['password']),
                    'pin' => Hash::make($validatedData['pin'])
                ]);

                $request->session()->put('email', $user->email);
                $token = $user->createToken('AuthToken')->plainTextToken;
                return response()->json(['token' => $token, 'user' => $user]);
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
                $token = $user->createToken('AuthToken')->plainTextToken;
                return response()->json(['token' => $token, 'user' => $user]);
            }

            $user = User::where('email', $request->email)->first();

            if (!$user) {
                return response()->json(['message' => 'User not found'], 404);
            }

            // Generate random OTP
            $otp = mt_rand(100000, 999999);

            // Store OTP in the database with the user's email
            $user->otp = $otp;
            $user->save();

            // Send email to user containing the OTP
            Mail::to($user->email)->send(new OtpVerificationMail($otp));

            return response()->json(['message' => 'OTP sent successfully']);

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
        $user = User::where('email', $request->email)->first();

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
}
