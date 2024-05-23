<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class wallet extends Model
{
    use HasFactory;
    protected $fillable = [
        'user_id',
        'wallet_id',
        'transaction_id',
        'account_name',
        'urbanPayTag',
        'account_email',
        'account_number',
        'currency',
        'bank_name',
        'bank_code',
        'balance',
        'account_reference',
        'status',
    ];
}
