<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\UserController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });


Route::post('/auth/register', [UserController::class, 'createUser']);
Route::post('/auth/login', [UserController::class, 'loginUser']);
Route::post('/auth/verifyOtp', [UserController::class, 'verifyOtp']);
Route::post('/auth/pin', [UserController::class, 'pin']);
Route::delete('/auth/deleteUser/{id}', [UserController::class, 'deleteUser']);
Route::get('/auth/singleUser/{id}', [UserController::class, 'singleUser']);
Route::put('/auth/updateUserProfile/', [UserController::class, 'updateUserProfile']);
Route::post('/auth/updateUserProfilePinVerify/', [UserController::class, 'updateUserProfilePinVerify']);
Route::post('/auth/updateUserProfilePasswordVerify/', [UserController::class, 'updateUserProfilePasswordVerify']);
Route::put('/auth/updateUserProfilePin/', [UserController::class, 'updateUserProfilePin']);
Route::put('/auth/updateUserProfilePassword/', [UserController::class, 'updateUserProfilePassword']);
Route::post('/auth/getbankList/', [UserController::class, 'getbankList']);
Route::post('/auth/verifyBank/', [UserController::class, 'verifyBank']);
Route::post('/auth/sendMoney/', [UserController::class, 'sendMoney']);
Route::post('/auth/sendMoneyWithTag/', [UserController::class, 'sendMoneyWithTag']);
Route::post('/auth/addMoney/', [UserController::class, 'addMoney']);
Route::post('/auth/transactionGet/', [UserController::class, 'transactionGet']);
Route::post('/auth/transactionGetALL/', [UserController::class, 'transactionGetALL']);
Route::post('/auth/listUser/', [UserController::class, 'listUser']);
Route::post('/auth/UserdetailsByteBridge/', [UserController::class, 'UserdetailsByteBridge']);
Route::post('/auth/BuyData/', [UserController::class, 'BuyData']);
Route::post('/auth/fetchDataTransaction/', [UserController::class, 'fetchDataTransaction']);
Route::post('/auth/fetchDataTransactionSingle/', [UserController::class, 'fetchDataTransactionSingle']);
Route::post('/auth/topUp/', [UserController::class, 'topUp']);
Route::post('/auth/FetchAirtimeTransactionSingle/', [UserController::class, 'FetchAirtimeTransactionSingle']);
Route::post('/auth/billPayment/', [UserController::class, 'billPayment']);
Route::post('/auth/subscribeToCable/', [UserController::class, 'subscribeToCable']);
Route::post('/auth/getCableSubscription/', [UserController::class, 'getCableSubscription']);
Route::post('/auth/validateIUC/', [UserController::class, 'validateIUC']);
Route::post('/auth/validateMeter/', [UserController::class, 'validateMeter']);
