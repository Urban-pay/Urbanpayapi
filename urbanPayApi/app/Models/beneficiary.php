<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class beneficiary extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'wallet_id',
        'transaction_id',
        'reference',
        'bank_code',
        'bank_name',
        'account_number',
        'account_name',
        'urbanPayTag',
    ];
}
