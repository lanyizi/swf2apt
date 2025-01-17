﻿namespace SwfLib.Actions {
    /// <summary>
    /// Represents StringDictByteGetVariable action.
    /// </summary>
    public class ActionStringDictByteGetVariable : ActionBase {

        /// <summary>
        /// Gets code of action.
        /// </summary>
        public override ActionCode ActionCode {
            get { return ActionCode.StringDictByteGetVariable; }
        }
        public byte Value { get; set; }

        /// <summary>
        /// Accept visitor.
        /// </summary>
        /// <typeparam name="TArg">Type of argument to be passed to visitor.</typeparam>
        /// <typeparam name="TResult">Type of result.</typeparam>
        /// <param name="visitor">Visitor.</param>
        /// <param name="arg">Argument to be passed to visitor.</param>
        /// <returns></returns>
        public override TResult AcceptVisitor<TArg, TResult>(IActionVisitor<TArg, TResult> visitor, TArg arg) {
            return visitor.Visit(this, arg);
        }

    }
}
