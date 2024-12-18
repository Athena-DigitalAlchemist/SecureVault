namespace SecureVault.Core.Models
{
    public class OperationResult<T>
    {
        public bool Success { get; set; }
        public T? Data { get; set; }
        public string? Message { get; set; }
        public string? ErrorCode { get; set; }
        public List<string> Errors { get; set; } = new List<string>();

        public static OperationResult<T> CreateSuccess(T data, string message = null)
        {
            return new OperationResult<T>
            {
                Success = true,
                Data = data,
                Message = message
            };
        }

        public static OperationResult<T> CreateError(string message, string errorCode = null, List<string> errors = null)
        {
            return new OperationResult<T>
            {
                Success = false,
                Message = message,
                ErrorCode = errorCode,
                Errors = errors ?? new List<string>()
            };
        }

        public static OperationResult<T> CreateError(Exception ex)
        {
            var result = new OperationResult<T>
            {
                Success = false,
                Message = ex.Message,
                Errors = new List<string> { ex.Message }
            };

            if (ex is SecureVault.Core.Exceptions.SecureVaultException svEx)
            {
                result.ErrorCode = svEx.ErrorCode;
            }

            return result;
        }
    }
}
