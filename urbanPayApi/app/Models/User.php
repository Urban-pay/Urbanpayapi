<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Laravel\Sanctum\HasApiTokens;

class user extends Authenticatable
{
    use HasApiTokens, HasFactory;

    protected $fillable = [
        'user_id',
        'name',
        'email',
        'username',
        'phoneno',
        'password',
        'pin',
        'otp',
        'firstName',
        'lastName'  ,
        'middleName',
        'phoneNumber',
        'addressLine_1'  ,
        'addressLine_2',
        'country',
        'city',
        'postalCode',
        'state',
        'isSoleProprietor',
        'description',
        'doingBusinessAs', 
        'gender',
        'dateOfBirth'  ,
        'selfieImage',
        'bvn',
        'idType',
        'idNumber',
        'expiryDate',  
    ];
}
